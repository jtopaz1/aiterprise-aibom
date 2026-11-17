"""Secrets analyzer (design doc 13 C32, basic MVP slice).

High-precision AI / cloud API-key detection in text files. The raw secret is
*never* surfaced: findings carry only a redacted preview and a short digest, and
the digest is what makes two different secrets in one file distinct findings.

Zero runtime dependencies: curated regexes + a placeholder filter, no entropy
library. `scan_secrets` only reads small text files and skips lockfiles,
minified bundles, binaries and model files.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

from . import sources
from .model import OWASP_SENSITIVE_INFO, Evidence, Finding, Location, ScanResult
from .textio import TooLarge, read_text
from .walk import rel_posix

MAX_SECRET_BYTES = 1 * 1024 * 1024  # files larger than this are not scanned for secrets


@dataclass
class SecretMatch:
    rule_id: str
    kind: str
    start: int
    line: int
    redacted: str
    digest: str  # sha256 hex prefix of the raw value; raw value is never stored


# Each rule: (rule_id, kind, compiled regex). Order matters only for overlap
# resolution (more specific prefixes first). Patterns are deliberately tight.
_RULES: list[tuple[str, str, re.Pattern[str]]] = [
    ("openai-project", "openai", re.compile(r"\bsk-proj-[A-Za-z0-9_-]{20,}\b")),
    ("openai-service", "openai", re.compile(r"\bsk-(?:svcacct|admin)-[A-Za-z0-9_-]{20,}\b")),
    ("anthropic", "anthropic", re.compile(r"\bsk-ant-(?:api03-|sid01-)?[A-Za-z0-9_-]{24,}\b")),
    ("openai-legacy", "openai", re.compile(r"\bsk-[A-Za-z0-9]{48}\b")),
    ("huggingface", "huggingface", re.compile(r"\bhf_[A-Za-z0-9]{34,40}\b")),
    ("github-pat", "github", re.compile(r"\bghp_[A-Za-z0-9]{36}\b")),
    ("github-oauth", "github", re.compile(r"\bgho_[A-Za-z0-9]{36}\b")),
    ("github-fine-grained", "github", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{60,}\b")),
    ("xai", "xai", re.compile(r"\bxai-[A-Za-z0-9]{32,}\b")),
    ("groq", "groq", re.compile(r"\bgsk_[A-Za-z0-9]{40,}\b")),
    ("replicate", "replicate", re.compile(r"\br8_[A-Za-z0-9]{37,40}\b")),
    ("aws-access-key", "aws", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("google-api-key", "google", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("slack-token", "slack", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b")),
    ("private-key-pem", "private-key",
     re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----")),
]

# A matched value that looks like one of these is a placeholder, not a secret.
_PLACEHOLDER_WORDS = re.compile(
    r"(?i)(?:your[_-]?api|yourkey|your[_-]?key|example|changeme|placeholder|redacted|"
    r"dummy|sample|testkey|xxxx+|000000|123456|abcdef|replace[_-]?me|insert[_-]?here|notreal|fake)")
_REPEAT_RUN = re.compile(r"(.)\1{7,}")  # 8+ identical chars in a row


def _is_placeholder(value: str) -> bool:
    if any(c in value for c in "<>${}"):
        return True
    if "..." in value or "…" in value:
        return True
    if _PLACEHOLDER_WORDS.search(value):
        return True
    if _REPEAT_RUN.search(value):
        return True
    # too few distinct characters for a real high-entropy token (ignore PEM headers)
    body = value.split("-", 2)[-1] if value.startswith("-----") else value
    alnum = [c for c in body if c.isalnum()]
    if len(alnum) >= 16 and len(set(alnum)) <= 4:
        return True
    return False


def redact(value: str) -> str:
    """A non-reversible preview: a short head and tail with a masked middle.

    Never returns enough of the value to reconstruct it.
    """
    v = value.strip()
    if v.startswith("-----BEGIN"):
        return v.split("\n", 1)[0].strip()
    if len(v) <= 8:
        return (v[:1] + "******") if v else "******"
    head, tail = v[:4], v[-4:]
    middle = "*" * min(max(len(v) - 8, 4), 12)
    return f"{head}{middle}{tail}"


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", "replace")).hexdigest()[:16]


def find_secrets(text: str) -> list[SecretMatch]:
    """Every distinct secret in `text`, placeholders filtered out, no overlaps."""
    raw: list[tuple[int, int, str, str]] = []  # (start, end, rule_id, kind)
    for rule_id, kind, rx in _RULES:
        for m in rx.finditer(text):
            value = m.group(0)
            if kind != "private-key" and _is_placeholder(value):
                continue
            raw.append((m.start(), m.end(), rule_id, kind))
    raw.sort(key=lambda t: (t[0], -(t[1] - t[0])))
    out: list[SecretMatch] = []
    covered = -1
    for start, end, rule_id, kind in raw:
        if start < covered:
            continue  # overlaps an already-accepted (longer/earlier) match
        covered = end
        value = text[start:end]
        out.append(SecretMatch(
            rule_id=rule_id,
            kind=kind,
            start=start,
            line=text.count("\n", 0, start) + 1,
            redacted=redact(value),
            digest=_digest(value),
        ))
    return out


def redact_secrets_in(text: str) -> str:
    """Return `text` with every detected secret replaced by its redacted preview."""
    spans: list[tuple[int, int, str]] = []  # (start, end, redacted)
    for _rule_id, kind, rx in _RULES:
        for m in rx.finditer(text):
            value = m.group(0)
            if kind != "private-key" and _is_placeholder(value):
                continue
            spans.append((m.start(), m.end(), redact(value)))
    if not spans:
        return text
    spans.sort(key=lambda t: (t[0], -(t[1] - t[0])))
    out: list[str] = []
    cursor = 0
    for start, end, red in spans:
        if start < cursor:
            continue
        out.append(text[cursor:start])
        out.append(red)
        cursor = end
    out.append(text[cursor:])
    return "".join(out)


# query parameters whose value is a credential however it looks (no provider prefix to match)
_SECRET_PARAM = re.compile(
    r"(?i)(?:token|secret|passw(?:or)?d|pwd|api[_-]?key|apikey|^key$|auth|^sig$|signature|^code$|"
    r"session|credential|access[_-]?key|private)")


def redact_url(url: str) -> str:
    """`url` with a userinfo password and credential-like query values masked, and any detected
    provider key redacted, so a config's server URL can be reported without leaking it."""
    text = redact_secrets_in(str(url))
    try:
        parts = urlsplit(text)
    except ValueError:
        return text
    netloc = parts.netloc
    if "@" in netloc:
        userinfo, host = netloc.rsplit("@", 1)
        user, sep, _password = userinfo.partition(":")
        netloc = f"{user}:******@{host}" if sep else f"{userinfo}@{host}"
    query = parts.query
    if query:
        pairs = []
        for pair in query.split("&"):
            name, sep, value = pair.partition("=")
            if sep and value and _SECRET_PARAM.search(name):
                value = redact(value)
            pairs.append(f"{name}{sep}{value}")
        query = "&".join(pairs)
    return urlunsplit((parts.scheme, netloc, parts.path, query, parts.fragment))


# ---- file scanning --------------------------------------------------------

_SKIP_NAMES = {
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock", "cargo.lock",
    "uv.lock", "pipfile.lock", "composer.lock", "gemfile.lock", "go.sum", "npm-shrinkwrap.json",
    "flake.lock", "bun.lockb", "packages.lock.json",
}
_SKIP_EXT = {
    ".pt", ".pth", ".bin", ".ckpt", ".pkl", ".pickle", ".joblib", ".safetensors", ".gguf",
    ".ggml", ".onnx", ".h5", ".hdf5", ".keras", ".tflite", ".mar", ".pte", ".npy", ".npz",
    ".pb", ".pdparams", ".msgpack", ".zip", ".gz", ".tar", ".tgz", ".xz", ".zst", ".7z",
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".pdf", ".woff", ".woff2", ".ttf",
    ".so", ".dll", ".dylib", ".exe", ".a", ".o", ".class", ".wasm", ".jar", ".bin",
    ".mp3", ".mp4", ".mov", ".wav", ".parquet", ".db", ".sqlite", ".sqlite3",
}
_TEXT_EXT = {
    ".env", ".py", ".pyi", ".js", ".cjs", ".mjs", ".ts", ".tsx", ".jsx", ".json", ".jsonc",
    ".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf", ".properties", ".sh", ".bash", ".zsh",
    ".fish", ".ps1", ".psm1", ".bat", ".cmd", ".md", ".markdown", ".mdx", ".txt", ".rst",
    ".xml", ".html", ".tpl", ".tmpl", ".prompt", ".prompty", ".mdc", ".j2", ".tf", ".tfvars", ".dockerfile",
    ".gradle", ".groovy", ".rb", ".go", ".rs", ".java", ".kt", ".php", ".cs", ".sql",
}
_TEXT_NAMES = {
    "dockerfile", ".npmrc", ".pypirc", ".netrc", ".dockercfg", ".flaskenv", "config",
    "credentials", ".git-credentials", "pip.conf",
    ".cursorrules", ".windsurfrules", ".clinerules", ".goosehints",  # agent instruction files (prompts)
}


def _is_scannable(path: Path) -> bool:
    name = path.name.lower()
    if name.startswith(".env"):
        return True
    if name in _SKIP_NAMES:
        return False
    if ".min." in name:  # minified bundle
        return False
    ext = path.suffix.lower()
    if ext in _SKIP_EXT:
        return False
    if ext in _TEXT_EXT or name in _TEXT_NAMES:
        return True
    return False


def _finding(match: SecretMatch, location: Location) -> Finding:
    kinds = {
        "openai": "OpenAI", "anthropic": "Anthropic", "huggingface": "Hugging Face",
        "github": "GitHub", "xai": "xAI", "groq": "Groq", "replicate": "Replicate",
        "aws": "AWS", "google": "Google", "slack": "Slack", "private-key": "private key",
    }
    label = kinds.get(match.kind, match.kind)
    return Finding(
        rule_id=f"ait.secret.{match.kind}",
        title=f"Hard-coded {label} credential",
        severity="high",
        verdict="suspicious",
        confidence=80,
        location=location,
        evidence=[Evidence(
            source="ait-secrets",
            record=match.rule_id,
            detail={"kind": match.kind, "redacted": match.redacted, "digest": match.digest[:8]},
        )],
        remediation=(
            "Remove the credential from source control, rotate it immediately, and load it "
            "from an environment variable or secret manager instead."),
        maps_to=[OWASP_SENSITIVE_INFO],
        discriminator=match.digest[:8],
    )


def scan_secrets(root: Path, files: list[Path], result: ScanResult | None = None) -> list[Finding]:
    """Scan every scannable text file for secrets and return high findings.

    Files skipped for size or read errors are counted in `result` (note + examined), so a large
    `.env` is never mistaken for one that was checked and found clean.
    """
    findings: list[Finding] = []
    checked = 0
    skipped: list[str] = []
    for path in files:
        if not _is_scannable(path):
            continue
        try:
            text = read_text(path, max_bytes=MAX_SECRET_BYTES)
        except (OSError, TooLarge):
            skipped.append(rel_posix(path, root))
            continue
        checked += 1
        for match in find_secrets(text):
            findings.append(_finding(match, Location(rel_posix(path, root), match.line)))
    if result is not None:
        ex = result.examine(sources.SECRETS.name)
        ex.checked += checked
        ex.with_data += len({f.location.path for f in findings if f.location})
        if skipped:
            shown = ", ".join(skipped[:5]) + (f" and {len(skipped) - 5} more" if len(skipped) > 5 else "")
            result.notes.append(f"secrets: {len(skipped)} text file(s) over {MAX_SECRET_BYTES // (1024 * 1024)} MiB "
                                f"or unreadable were not scanned ({shown})")
    return findings
