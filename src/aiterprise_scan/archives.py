"""Package archives and MCP bundles, read member by member without extracting them (design doc 13 §4.1).

Inputs: wheels / eggs (`.whl`, `.egg`), sdists and npm tarballs (`.tar.gz`, `.tgz`, `.tar.bz2`,
`.tar.xz`), zip sdists (only when they hold `PKG-INFO` / `setup.py` / `pyproject.toml`) and MCP
bundles (`.mcpb`, `.dxt`).

What is judged:
- the package itself (`METADATA` / `PKG-INFO` / `package/package.json`) becomes a component, so the
  malicious-version, advisory and registry checks see it;
- `.pth` files run at every Python start-up: an executed payload (exec/eval of decoded data) is
  critical, network or process calls high, any other start-up code low;
- install-time code: npm lifecycle scripts and `setup.py` against the command rules, and `setup.py`
  that executes decoded data;
- model files inside the archive go through the model-file analyzer (never unpickled);
- members that would land outside the extraction directory (absolute paths, `..`, links that point
  outside) — the archive is hostile or broken whatever else it holds.

An archive that cannot be read, or a member over the caps, is reported as not analysable.
"""

from __future__ import annotations

import json
import re
import tarfile
import tempfile
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from . import mcpb, modelfiles
from .model import (
    OWASP_SUPPLY_CHAIN,
    Component,
    Evidence,
    Finding,
    Location,
    not_analysable,
)
from .textio import decode_bytes
from .walk import rel_posix

MAX_MEMBERS = 20_000
MAX_TEXT_BYTES = 4 * 1024 * 1024
MAX_MODEL_BYTES = 512 * 1024 * 1024
MAX_TOTAL_BYTES = 2 * 1024 * 1024 * 1024
MAX_TAR_BYTES = 512 * 1024 * 1024  # a compressed tar is read front to back; bigger ones are reported, not read
_TAR_SUFFIXES = (".tar.gz", ".tgz", ".tar.bz2", ".tbz2", ".tar.xz", ".txz", ".tar")
_ZIP_SUFFIXES = (".whl", ".egg", ".mcpb", ".dxt", ".zip")
NPM_LIFECYCLE = ("preinstall", "install", "postinstall", "prepare")

_DECODE = r"(?:b64decode|base64|a85decode|b32decode|zlib\.decompress|bz2\.decompress|lzma\.decompress|" \
          r"marshal\.loads|codecs\.decode|bytes\.fromhex|\.decode\(\s*['\"]hex|rot.?13|\\x[0-9a-fA-F]{2})"
_EXEC_PAYLOAD = re.compile(r"\b(?:exec|eval|compile)\s*\(.{0,400}?" + _DECODE + r"|" + _DECODE +
                           r".{0,400}?\b(?:exec|eval)\s*\(", re.S)
_NET_OR_PROC = re.compile(r"\b(?:subprocess|os\.system|os\.popen|pty\.spawn|urllib\.request|urlopen|"
                          r"requests\.(?:get|post)|http\.client|socket\.socket|ftplib)\b")


def is_archive_candidate(path: Path) -> bool:
    name = path.name.lower()
    return name.endswith(_TAR_SUFFIXES) or name.endswith(_ZIP_SUFFIXES)


@dataclass
class _Member:
    name: str
    size: int
    kind: str = "file"  # file | dir | link | special
    target: str = ""


class _Archive:
    """Uniform member access over zip and tar, with size caps."""

    def __init__(self, path: Path) -> None:
        self.path = path
        low = path.name.lower()
        self.zip: zipfile.ZipFile | None = None
        self.tar: tarfile.TarFile | None = None
        if low.endswith(_ZIP_SUFFIXES):
            self.zip = zipfile.ZipFile(path)
        else:
            self.tar = tarfile.open(path, mode="r:*")
        self._tar_index: dict[str, tarfile.TarInfo] = {}

    def close(self) -> None:
        (self.zip or self.tar).close()  # type: ignore[union-attr]

    def members(self) -> list[_Member]:
        out: list[_Member] = []
        if self.zip is not None:
            for info in self.zip.infolist()[: MAX_MEMBERS + 1]:
                out.append(_Member(info.filename, info.file_size, "dir" if info.is_dir() else "file"))
            return out
        assert self.tar is not None
        for i, info in enumerate(self.tar):
            if i > MAX_MEMBERS:
                break
            kind = "file" if info.isfile() else "dir" if info.isdir() else \
                "link" if (info.issym() or info.islnk()) else "special"
            out.append(_Member(info.name, info.size, kind, info.linkname or ""))
            if kind == "file":
                self._tar_index.setdefault(info.name, info)
        return out

    def read(self, name: str, cap: int) -> bytes | None:
        """Up to `cap` bytes; None when the member is larger than the cap."""
        if self.zip is not None:
            with self.zip.open(name) as fh:
                blob = fh.read(cap + 1)
        else:
            info = self._tar_index.get(name)
            fh = self.tar.extractfile(info) if (self.tar is not None and info is not None) else None
            if fh is None:
                return b""
            blob = fh.read(cap + 1)
        return None if len(blob) > cap else blob


def _escapes(name: str) -> bool:
    if name.startswith(("/", "\\")) or re.match(r"^[A-Za-z]:", name):
        return True
    parts = PurePosixPath(name.replace("\\", "/")).parts
    depth = 0
    for p in parts:
        if p == "..":
            depth -= 1
            if depth < 0:
                return True
        elif p not in (".", ""):
            depth += 1
    return False


def _link_escapes(member: _Member) -> bool:
    if not member.target:
        return False
    if member.target.startswith(("/", "\\")) or re.match(r"^[A-Za-z]:", member.target):
        return True
    base = PurePosixPath(member.name.replace("\\", "/")).parent
    return _escapes(str(base / member.target))


def _headers(text: str) -> dict[str, str]:
    """RFC 822-style METADATA / PKG-INFO headers (first occurrence wins; body ignored)."""
    out: dict[str, str] = {}
    for line in text.splitlines():
        if not line.strip():
            break
        key, sep, value = line.partition(":")
        if sep and not line.startswith((" ", "\t")):
            out.setdefault(key.strip().lower(), value.strip())
    return out


def _finding(rule: str, title: str, sev: str, verdict: str, conf: int, comp: Component | None, where: str,
             remediation: str, detail: dict, discriminator: str = "") -> Finding:
    return Finding(rule_id=rule, title=title, severity=sev, verdict=verdict, confidence=conf, component=comp,
                   location=Location(where), evidence=[Evidence("ait-rules", rule.rsplit(".", 1)[-1], None, detail)],
                   remediation=remediation, maps_to=[OWASP_SUPPLY_CHAIN], discriminator=discriminator or where)


def _pth_findings(text: str, where: str, comp: Component | None) -> list[Finding]:
    code = [ln for ln in text.splitlines() if ln.lstrip().startswith(("import ", "import\t"))]
    if not code:
        return []  # plain path entries: no code runs
    joined = "\n".join(code)
    if _EXEC_PAYLOAD.search(joined):
        return [_finding(
            "ait.archive.pth-exec-payload", f"{where.rsplit('!', 1)[-1]} decodes and executes code at every Python "
            "start-up", "critical", "malicious", 90, comp, where,
            "Do not install this package. A .pth file that executes a decoded payload runs on every interpreter "
            "start, including in CI; rotate credentials of any environment that installed it.",
            {"lines": len(code), "pattern": "exec of decoded data"})]
    if _NET_OR_PROC.search(joined):
        return [_finding(
            "ait.archive.pth-network-or-process", f"{where.rsplit('!', 1)[-1]} starts processes or opens network "
            "connections at every Python start-up", "high", "suspicious", 75, comp, where,
            "Review the .pth file before installing; start-up hooks rarely need the network or a shell.",
            {"lines": len(code)})]
    return [_finding(
        "ait.archive.pth-startup-code", f"{where.rsplit('!', 1)[-1]} runs code at every Python start-up",
        "low", "unknown", 60, comp, where,
        "Usually a namespace-package or tooling hook; confirm the package is expected to install one.",
        {"lines": len(code)})]


def _setup_py_findings(text: str, where: str, comp: Component | None) -> list[Finding]:
    from . import mcp

    out: list[Finding] = []
    if _EXEC_PAYLOAD.search(text):
        out.append(_finding(
            "ait.archive.setup-exec-payload", "setup.py executes decoded code when the package is built or installed",
            "critical", "malicious", 85, comp, where,
            "Do not install this sdist; building it runs the hidden payload with your permissions.",
            {"pattern": "exec of decoded data"}))
    for hit in mcp.check_command(text):
        out.append(_cmd_finding(hit, where, comp, "setup.py"))
    return out


def _cmd_finding(hit: dict, where: str, comp: Component | None, script: str) -> Finding:
    from .mcp import _CONF

    verdict, conf = _CONF[hit["severity"]]
    return _finding(f"ait.archive.cmd.{hit['id']}", f"Install-time {script} runs a dangerous command: "
                    f"{hit['description']}", hit["severity"], verdict, conf, comp, where, hit["remediation"],
                    {"category": hit["category"], "match": hit["match"], "script": script},
                    discriminator=f"{where}:{script}:{hit['id']}")


def _model_members(arc: _Archive, members: list[_Member], arc_rel: str, budget: list[int]
                   ) -> tuple[list[Component], list[Finding]]:
    comps: list[Component] = []
    finds: list[Finding] = []
    with tempfile.TemporaryDirectory(prefix="ait-arc-") as tmp:
        for i, m in enumerate(members):
            where = f"{arc_rel}!{m.name}"
            if m.size > MAX_MODEL_BYTES or m.size > budget[0]:
                finds.append(not_analysable("model", where, f"Model file {m.name}", "larger than the archive cap"))
                continue
            blob = arc.read(m.name, MAX_MODEL_BYTES)
            if blob is None:
                finds.append(not_analysable("model", where, f"Model file {m.name}", "larger than the archive cap"))
                continue
            budget[0] -= len(blob)
            local = Path(tmp) / f"{i}-{PurePosixPath(m.name).name}"
            local.write_bytes(blob)
            comp, fs = modelfiles.analyze_model_file(local, Path(tmp))
            if comp is None:
                continue
            comp.name = PurePosixPath(m.name).name
            comp.locations = [Location(where)]
            comp.properties["path"] = where
            comp.properties["archive"] = arc_rel
            for f in fs:
                f.location = Location(where)
                f.component = comp
            comps.append(comp)
            finds.extend(fs)
    return comps, finds


def analyze_archive(path: Path, root: Path) -> tuple[list[Component], list[Finding]]:
    arc_rel = rel_posix(path, root)
    try:
        if path.name.lower().endswith(_TAR_SUFFIXES) and path.stat().st_size > MAX_TAR_BYTES:
            return [], [not_analysable("archive", arc_rel, f"Archive {path.name}",
                                       f"larger than {MAX_TAR_BYTES // (1024 * 1024)} MiB")]
        arc = _Archive(path)
    except (zipfile.BadZipFile, tarfile.TarError, OSError, EOFError, ValueError) as err:
        if path.name.lower().endswith(".zip"):
            return [], []  # a broken zip of unknown purpose is not a package we were asked about
        return [], [not_analysable("archive", arc_rel, f"Archive {path.name}", f"unreadable: {type(err).__name__}")]
    try:
        return _analyze_open(arc, path, arc_rel)
    except (zipfile.BadZipFile, tarfile.TarError, OSError, EOFError, ValueError, RuntimeError) as err:
        return [], [not_analysable("archive", arc_rel, f"Archive {path.name}", f"unreadable: {type(err).__name__}")]
    finally:
        arc.close()


def _analyze_open(arc: _Archive, path: Path, arc_rel: str) -> tuple[list[Component], list[Finding]]:
    members = arc.members()
    findings: list[Finding] = []
    comps: list[Component] = []
    if len(members) > MAX_MEMBERS:
        findings.append(not_analysable("archive", arc_rel, f"Archive {path.name}",
                                       f"more than {MAX_MEMBERS:,} members"))
        members = members[:MAX_MEMBERS]
    files = {m.name: m for m in members if m.kind == "file"}
    low = path.name.lower()

    # what is this archive?
    pkg: Component | None = None
    meta_name = next((n for n in files if re.fullmatch(r"[^/]+\.dist-info/METADATA", n)), None) \
        or next((n for n in files if re.fullmatch(r"(?:[^/]+/)?PKG-INFO", n)), None) \
        or next((n for n in files if re.fullmatch(r"EGG-INFO/PKG-INFO", n)), None)
    npm_json = files.get("package/package.json")
    manifest = files.get("manifest.json") if low.endswith((".mcpb", ".dxt", ".zip")) else None
    is_sdist_zip = low.endswith(".zip") and (meta_name or any(re.fullmatch(r"[^/]+/(setup\.py|pyproject\.toml)", n)
                                                              for n in files))
    if low.endswith(".zip") and not is_sdist_zip and manifest is None:
        return [], []  # an ordinary zip, not a package or bundle
    if meta_name:
        hdr = _headers(decode_bytes(arc.read(meta_name, MAX_TEXT_BYTES) or b""))
        if hdr.get("name"):
            pkg = Component(hdr["name"], ecosystem="pypi", version=hdr.get("version") or None,
                            locations=[Location(arc_rel)], source="archive",
                            properties={"archive": arc_rel, "direct": True})
    elif npm_json:
        try:
            doc = json.loads(decode_bytes(arc.read("package/package.json", MAX_TEXT_BYTES) or b"{}"))
        except ValueError:
            doc = {}
        if isinstance(doc, dict) and isinstance(doc.get("name"), str):
            pkg = Component(doc["name"], ecosystem="npm",
                            version=doc.get("version") if isinstance(doc.get("version"), str) else None,
                            locations=[Location(arc_rel)], source="archive",
                            properties={"archive": arc_rel, "direct": True})
            scripts = doc.get("scripts") if isinstance(doc.get("scripts"), dict) else {}
            from . import mcp

            for hook in NPM_LIFECYCLE:
                if isinstance(scripts.get(hook), str):
                    for hit in mcp.check_command(scripts[hook]):
                        findings.append(_cmd_finding(hit, f"{arc_rel}!package/package.json", pkg, hook))
    if pkg is not None:
        from . import taxonomy

        pkg.ai = taxonomy.is_ai_package(pkg.name, pkg.ecosystem)
        comps.append(pkg)

    if manifest is not None:
        try:
            doc = json.loads(decode_bytes(arc.read("manifest.json", MAX_TEXT_BYTES) or b"{}"))
        except ValueError:
            doc = None
        if mcpb.is_bundle_manifest(doc):
            kind = "dxt" if low.endswith(".dxt") or "dxt_version" in doc else "mcpb"
            c, fs = mcpb.analyze_manifest(doc, f"{arc_rel}!manifest.json", kind)
            comps.append(c)
            findings.extend(fs)
        elif not is_sdist_zip:
            return [], []

    # members
    model_members: list[_Member] = []
    for m in members:
        where = f"{arc_rel}!{m.name}"
        if _escapes(m.name) or (m.kind == "link" and _link_escapes(m)) or m.kind == "special":
            reason = "a device or special file" if m.kind == "special" else \
                f"a link to {m.target}" if m.kind == "link" else "a path outside the extraction directory"
            findings.append(_finding(
                "ait.archive.path-traversal", f"{path.name} contains {reason} ({m.name})", "high", "suspicious",
                90, pkg, where, "Do not extract this archive with tools that follow such entries; treat it as "
                "hostile or broken and obtain the package from its registry.", {"member": m.name[:300]}))
            continue
        if m.kind != "file":
            continue
        base = PurePosixPath(m.name).name
        if base.endswith(".pth"):
            blob = arc.read(m.name, MAX_TEXT_BYTES)
            if blob is not None and b"\x00" not in blob[:4096] and not blob.startswith((b"PK", b"\x80")):
                findings.extend(_pth_findings(decode_bytes(blob), where, pkg))
                continue
        if base == "setup.py" and m.name.count("/") <= 1:
            blob = arc.read(m.name, MAX_TEXT_BYTES)
            if blob is None:
                findings.append(not_analysable("archive", where, "setup.py", "larger than the text cap"))
            else:
                findings.extend(_setup_py_findings(decode_bytes(blob), where, pkg))
            continue
        if modelfiles.is_model_candidate(Path(base)):
            model_members.append(m)
    if model_members:
        mc, mf = _model_members(arc, model_members, arc_rel, [MAX_TOTAL_BYTES])
        comps.extend(mc)
        findings.extend(mf)
    return comps, findings


def find_bundle_manifests(files: list[Path]) -> list[Path]:
    return [f for f in files if f.name == "manifest.json"]


def analyze_unpacked_manifest(path: Path, root: Path) -> tuple[list[Component], list[Finding]]:
    from .textio import read_json, TooLarge

    try:
        doc = read_json(path)
    except (OSError, ValueError, TooLarge):
        return [], []
    if not mcpb.is_bundle_manifest(doc):
        return [], []
    comp, fs = mcpb.analyze_manifest(doc, rel_posix(path, root), "manifest")
    return [comp], fs


def analyze(root: Path, files: list[Path], result) -> tuple[list[Component], list[Finding]]:
    comps: list[Component] = []
    finds: list[Finding] = []
    ex = result.examine("archives")
    for path in files:
        if is_archive_candidate(path):
            c, f = analyze_archive(path, root)
            if c or f:
                ex.checked += 1
                ex.with_data += 1 if f else 0
            comps += c
            finds += f
        elif path.name == "manifest.json":
            c, f = analyze_unpacked_manifest(path, root)
            if c:
                ex.checked += 1
                ex.with_data += 1 if f else 0
            comps += c
            finds += f
    return comps, finds


