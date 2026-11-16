"""SecDB API v1 client and scan enrichment (design doc 13 §4.8, Appendix I/K; contract `14a` v2.14).

Production: `https://secdb.aiterprise.net` (override with `AITERPRISE_SECDB_URL`). The scanner uses
SecDB only when this machine holds a credential (`aiterprise-scan login`, or `AITERPRISE_API_KEY`);
`--offline` and `--no-secdb` never call it.

Client obligations implemented here (`14a` §2, §4): purls, hashes and URLs travel in POST bodies;
private MCP URLs are checked by an 8-hex SHA-256 prefix only (k-anonymity) and compared locally;
metered POSTs carry an `Idempotency-Key`; 502/503 are retried with backoff, 429 is not retried
during a scan — the scan degrades and reports the rest as UNVERIFIED, never as safe; limits come
from `GET /v1/me`, never from constants; `notices[]` are kept for every report; `unknown` is never
read as safety, and an MCP assessment of `clean` is never presented as safe.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import os
import sys
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable
from urllib.parse import quote, urlencode

from . import __version__, net, providers, reportdoc, sources
from .credentials import Credential
from .model import (
    OWASP_SUPPLY_CHAIN,
    Component,
    Evidence,
    Finding,
    ScanResult,
)

DEFAULT_BASE_URL = "https://secdb.aiterprise.net"
APP = "aiterprise-scan"
CONSENT_TEXT_VERSION = "2026-11"
MCP_PREFIX_HEX = 8
DEFAULT_PER_MINUTE = 20  # only when /v1/me reports no per-minute limit
PAID_PLANS = {"starter", "pro", "team", "business", "enterprise"}

Transport = Callable[[str, str, Any, dict], net.Response]


def base_url() -> str:
    return os.environ.get("AITERPRISE_SECDB_URL", DEFAULT_BASE_URL).rstrip("/")


def _http(method: str, url: str, body: Any, headers: dict) -> net.Response:
    # 429 is not retried inside a scan: the scan degrades instead of stalling (`14a` §3.2)
    return net.request(method, url, body, headers, timeout=20.0, ok=(304,), retry_on={502, 503})


DEFAULT_TRANSPORT: Transport = _http


class SecDBError(Exception):
    def __init__(self, err: net.NetError) -> None:
        self.status = err.status
        self.type = err.problem_type
        self.title = str(err.problem.get("title") or "")
        self.detail = str(err.problem.get("detail") or "")
        self.request_id = str(err.problem.get("request_id") or err.headers.get("x-request-id") or "")
        self.violated = list(err.problem.get("violated_policies") or [])
        self.cause = str(err)
        what = " ".join(x for x in (str(self.status or ""), self.type) if x) or str(err)
        text = f"SecDB {what}"
        if self.title:
            text += f": {self.title}"
        if self.detail:
            text += f" — {self.detail}"
        if self.request_id:
            text += f" (request {self.request_id})"
        if self.status is None:
            text = f"SecDB unreachable: {err}"
        super().__init__(text)

    @property
    def quota(self) -> bool:
        return self.status == 429


def platform_name() -> str:
    if sys.platform == "win32":
        return "windows"
    if sys.platform == "darwin":
        return "macos"
    return "linux" if sys.platform.startswith("linux") else "other"


def _now() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass
class Client:
    credential: Credential | None
    base_url: str | None = None
    transport: Transport | None = None
    sleep: Callable[[float], None] = field(default=lambda s: None)

    def __post_init__(self) -> None:
        self.base_url = (self.base_url or base_url()).rstrip("/")
        self.transport = self.transport or DEFAULT_TRANSPORT

    def _call(self, method: str, path: str, body: Any = None, query: dict | None = None, metered: bool = False,
              auth: bool = True, headers: dict | None = None) -> net.Response:
        url = f"{self.base_url}{path}"
        if query:
            url += "?" + urlencode({k: v for k, v in query.items() if v is not None})
        hdrs = dict(headers or {})
        if auth and self.credential is not None:
            hdrs["Authorization"] = f"Bearer {self.credential.secret}"
        if metered:
            hdrs["Idempotency-Key"] = str(uuid.uuid4())
        try:
            return self.transport(method, url, body, hdrs)  # type: ignore[misc]
        except net.NetError as err:
            raise SecDBError(err) from None

    # account ----------------------------------------------------------------------------
    def me(self) -> dict:
        return self._call("GET", "/v1/me").data or {}

    def usage(self) -> dict:
        return self._call("GET", "/v1/usage").data or {}

    def register_install(self) -> dict:
        body = {"app": APP, "app_version": __version__[:40], "platform": platform_name()}
        return self._call("POST", "/v1/installs", body, auth=False).data or {}

    # judgements -------------------------------------------------------------------------
    def lookup(self, kind: str, value: str, channel: str | None = None) -> dict:
        body = {"kind": kind, "value": value, **({"channel": channel} if channel else {})}
        return self._call("POST", "/v1/lookup", body, metered=True).data or {}

    def lookup_batch(self, items: list[dict]) -> dict:
        return self._call("POST", "/v1/lookup/batch", {"items": items}, metered=True).data or {}

    def lookup_prefixes(self, space: str, prefixes: list[str]) -> dict:
        return self._call("POST", "/v1/lookup/prefixes", {"space": space, "prefixes": prefixes}, metered=True).data or {}

    def mcp_assessment(self, name: str) -> dict:
        return self._call("GET", f"/v1/mcp/{quote(name, safe='/')}").data or {}

    def file_verdict(self, digest: str) -> dict:
        return self._call("POST", "/v1/verdict/file", {"hash": digest.lower()}, metered=True).data or {}

    # definitions ------------------------------------------------------------------------
    def releases_latest(self, domain: str, fmt: str, channel: str | None = None,
                        etag: str | None = None) -> dict | None:
        """The latest release, or None when it is unchanged (304)."""
        resp = self._call("GET", "/v1/releases/latest", query={"domain": domain, "format": fmt, "channel": channel},
                          headers={"If-None-Match": f'"{etag}"'} if etag else None)
        return None if resp.status == 304 else (resp.data or {})

    # feedback and uploads ---------------------------------------------------------------
    def report(self, rtype: str, rule_id: str | None = None, notes: str | None = None,
               indicator: dict | None = None, release_id: str | None = None) -> dict:
        if rule_id and providers.is_external(rule_id):
            # a BYO provider's result is not ours to collect (design doc 13 FD22)
            raise ValueError(f"{rule_id} is a third-party provider result; it is never sent to AIterprise")
        body: dict[str, Any] = {"type": rtype, "consent": {"basis": "user_consent",
                                                           "text_version": CONSENT_TEXT_VERSION,
                                                           "given_at": _now()}}
        if rule_id:
            body["rule_id"] = rule_id[:200]
        if notes:
            body["notes"] = notes[:2000]
        if indicator:
            body["indicator"] = indicator
        if release_id:
            body["release_id"] = release_id
        return self._call("POST", "/v1/reports", body, metered=True).data or {}

    def upload_scan(self, project: str, document: dict, scanned_at: str, fmt: str = "aiterprise-json") -> dict:
        # the last hop before SecDB or a cloud: only the upload view of a report document passes
        # it, so BYO provider results (FD22) and local paths never do
        document, _kept_local = reportdoc.upload_view(document)
        body = {"project": project[:200], "scanner_version": __version__[:40], "scanned_at": scanned_at,
                "format": fmt, "document": document}
        return self._call("POST", "/v1/aibom/scans", body, metered=True).data or {}

    def scan_status(self, scan_id: str) -> dict:
        return self._call("GET", f"/v1/aibom/scans/{quote(scan_id, safe='')}").data or {}


# --------------------------------------------------------------------------------------------
# Scan enrichment
# --------------------------------------------------------------------------------------------

_PKG_SEVERITY = {"malicious": ("critical", "malicious"), "suspicious": ("high", "suspicious")}
_HASH_SEVERITY = {"malicious": ("high", "malicious"), "suspicious": ("medium", "suspicious")}
_MCP_SEVERITY = {"malicious": ("high", "malicious"), "suspicious": ("medium", "suspicious")}


def _public_sources(res: dict) -> list[str]:
    return [str(p.get("name")) for p in res.get("provenance") or []
            if isinstance(p, dict) and p.get("public_display") is not False and p.get("name")]


def _evidence(res: dict, record: str | None = None) -> Evidence:
    detail: dict[str, Any] = {"verdict": res.get("verdict"), "confidence": res.get("confidence")}
    for key in ("categories", "family", "first_seen", "last_seen", "channel"):
        if res.get(key):
            detail[key] = res[key]
    sources = _public_sources(res)
    if sources:
        detail["sources"] = sources
    if isinstance(res.get("examined"), dict):
        detail["examined"] = res["examined"]
    if isinstance(res.get("conflict"), dict) and res["conflict"].get("flag"):
        detail["conflict"] = res["conflict"].get("note") or True
    return Evidence("secdb", record or res.get("release"), None, detail)


@dataclass
class _Item:
    kind: str  # file | mcp-url | package | mcp-name
    comp: Component
    value: str
    cost: int = 1


def _items(components: list[Component], key_only_ok: bool) -> list[_Item]:
    files, urls, ai_pkgs, pkgs, names = [], [], [], [], []
    for c in components:
        if c.ctype == "model-file" and c.hashes.get("sha256"):
            files.append(_Item("file", c, c.hashes["sha256"].lower()))
        elif c.ctype == "mcp-server" and isinstance(c.properties.get("url"), str):
            urls.append(_Item("mcp-url", c, c.properties["url"]))
        elif c.ctype == "mcp-server" and key_only_ok and isinstance(c.properties.get("registry_name"), str):
            names.append(_Item("mcp-name", c, c.properties["registry_name"]))
        elif c.ctype == "library" and c.version and c.purl:
            (ai_pkgs if c.ai else pkgs).append(_Item("package", c, c.purl))
    return files + urls + names + ai_pkgs + pkgs


def _finding_for(item: _Item, res: dict) -> Finding | None:
    verdict = res.get("verdict")
    comp = item.comp
    if item.kind == "package" and verdict in _PKG_SEVERITY:
        sev, ver = _PKG_SEVERITY[verdict]
        cats = ", ".join(res.get("categories") or []) or verdict
        return Finding(f"ait.pkg.secdb.{verdict}", f"SecDB rates {comp.name} {comp.version} {verdict} ({cats})", sev, ver,
                       int(res.get("confidence") or 70), comp, evidence=[_evidence(res)],
                       remediation="Review the SecDB evidence; remove or replace the package if it is confirmed.",
                       maps_to=[OWASP_SUPPLY_CHAIN])
    if item.kind == "file" and verdict in _HASH_SEVERITY:
        sev, ver = _HASH_SEVERITY[verdict]
        family = f" ({res['family']})" if res.get("family") else ""
        return Finding(f"ait.model.hash.{verdict}", f"{comp.name} matches a known-{verdict} file hash{family}", sev, ver,
                       int(res.get("confidence") or 70), comp, evidence=[_evidence(res)],
                       remediation="Do not load this file; obtain the model from its official publisher and compare hashes.",
                       maps_to=[OWASP_SUPPLY_CHAIN])
    if item.kind == "mcp-url" and verdict in _MCP_SEVERITY:
        sev, ver = _MCP_SEVERITY[verdict]
        return Finding(f"ait.mcp.secdb.{verdict}", f"MCP server {comp.name}: its URL is listed as {verdict} by SecDB",
                       sev, ver, int(res.get("confidence") or 70), comp, evidence=[_evidence(res, "mcp-prefix")],
                       remediation="Disconnect the server until its operator and endpoint are confirmed.",
                       maps_to=[OWASP_SUPPLY_CHAIN])
    return None


def _assessment_finding(item: _Item, res: dict) -> Finding | None:
    a = res.get("assessment") or {}
    tier = a.get("tier")
    item.comp.properties["secdb_assessment"] = {"tier": tier, "risk": a.get("risk"), "provenance": a.get("provenance"),
                                                "reputation": a.get("reputation"),
                                                "what_this_does_not_mean": res.get("what_this_does_not_mean")}
    if tier not in ("risky", "suspicious"):
        return None  # `clean` is provenance context, not a statement of safety
    sev = "medium" if tier == "risky" else "low"
    detail = {"tier": tier, "signals": [{"code": s.get("code"), "bucket": s.get("bucket")}
                                        for s in res.get("signals") or [] if isinstance(s, dict)],
              "auditable": (res.get("provenance") or {}).get("auditable"),
              "what_this_does_not_mean": res.get("what_this_does_not_mean")}
    return Finding(f"ait.mcp.reputation.{tier}", f"MCP server {item.value}: SecDB provenance assessment is {tier}", sev,
                   "suspicious", 60, item.comp, evidence=[Evidence("secdb", "mcp-assessment", None, detail)],
                   remediation="Prefer servers with an auditable source repository and a stable publisher.",
                   maps_to=[OWASP_SUPPLY_CHAIN])


def enrich(components: list[Component], result: ScanResult, client: Client) -> list[Finding]:
    examined = result.examine(sources.SECDB.name)
    try:
        me = client.me()
    except SecDBError as err:
        examined.errors += 1
        result.notes.append(f"secdb: {err}; SecDB judgements UNVERIFIED, not safe")
        return []
    limits = me.get("limits") or {}
    budget = int(limits.get("lookups_per_minute") or DEFAULT_PER_MINUTE)
    key_only_ok = me.get("credential") == "api_key"
    batch_ok = me.get("credential") == "install_token" or str(me.get("plan", "")).lower() in PAID_PLANS
    items = _items(components, key_only_ok)
    findings: list[Finding] = []
    used = 0
    stopped: str | None = None
    left: list[_Item] = []

    def account(res: dict) -> None:
        examined.checked += 1
        if res.get("verdict") not in (None, "unknown") or res.get("assessment"):
            examined.with_data += 1
        result.add_notices(res.get("notices"))

    # private MCP URLs: one prefix request for all of them
    urls = [i for i in items if i.kind == "mcp-url"]
    rest = [i for i in items if i.kind != "mcp-url"]
    if urls and used + len(urls) <= budget:
        digests = {i.value: hashlib.sha256(i.value.encode("utf-8")).hexdigest() for i in urls}
        try:
            resp = client.lookup_prefixes("mcp", sorted({d[:MCP_PREFIX_HEX] for d in digests.values()}))
            used += len(urls)
            result.add_notices(resp.get("notices"))
            entries = {h.get("sha256"): h for b in resp.get("buckets") or [] for h in b.get("hashes") or []}
            for i in urls:
                hit = entries.get(digests[i.value]) or {"verdict": "unknown"}
                account(hit)
                f = _finding_for(i, hit)
                if f:
                    findings.append(f)
        except SecDBError as err:
            stopped = _stop(err, examined, result)
    elif urls:
        left += urls

    pkgs = [i for i in rest if i.kind == "package"]
    singles = [i for i in rest if i.kind != "package"]
    if batch_ok and len(pkgs) > 1:
        singles_then = singles
        batch = pkgs
    else:
        singles_then = singles + pkgs
        batch = []

    for item in singles_then:
        if stopped:
            left.append(item)
            continue
        if used + item.cost > budget:
            left.append(item)
            continue
        try:
            if item.kind == "file":
                res = client.file_verdict(item.value)
            elif item.kind == "mcp-name":
                res = client.mcp_assessment(item.value)
            else:
                res = client.lookup("package", item.value)
        except SecDBError as err:
            if err.status == 404 and item.kind == "mcp-name":
                used += 1
                examined.checked += 1  # anti-oracle 404: no assessment, never "clean"
                continue
            stopped = _stop(err, examined, result)
            left.append(item)
            continue
        used += item.cost
        account(res)
        f = _assessment_finding(item, res) if item.kind == "mcp-name" else _finding_for(item, res)
        if f:
            findings.append(f)

    if batch and not stopped:
        room = max(0, budget - used)
        chunk, overflow = batch[:room], batch[room:]
        left += overflow
        if chunk:
            try:
                resp = client.lookup_batch([{"kind": "package", "value": i.value} for i in chunk])
                for entry in resp.get("results") or []:
                    idx = entry.get("index")
                    if not isinstance(idx, int) or not 0 <= idx < len(chunk):
                        continue
                    if entry.get("result"):
                        account(entry["result"])
                        f = _finding_for(chunk[idx], entry["result"])
                        if f:
                            findings.append(f)
                used += len(chunk)
            except SecDBError as err:
                stopped = _stop(err, examined, result)
                left += chunk
    elif batch:
        left += batch

    if left:
        why = stopped or f"per-minute limit of {budget} lookups"
        result.notes.append(f"secdb: {len(left)} item(s) not looked up ({why}); their SecDB status is UNVERIFIED, "
                            "not safe")
    return findings


def _stop(err: SecDBError, examined, result: ScanResult) -> str:
    if err.quota:
        result.notes.append(f"secdb: quota reached ({err.type or '429'}"
                            + (f", {', '.join(err.violated)}" if err.violated else "") + "); "
                            "remaining SecDB checks UNVERIFIED, not safe")
        return "quota reached"
    if err.status in (401, 403):
        result.notes.append(f"secdb: {err}; remaining SecDB checks skipped")
        examined.skipped = f"{err.status} {err.type}".strip()
        return "credential not allowed"
    examined.errors += 1
    result.notes.append(f"secdb: {err}; remaining SecDB checks UNVERIFIED, not safe")
    return "SecDB error"
