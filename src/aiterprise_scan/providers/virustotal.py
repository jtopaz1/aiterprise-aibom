"""VirusTotal adapter: file reputation by SHA-256, with the customer's own API key.

One call per file: `GET {base}/api/v3/files/{sha256}` with the header `x-apikey`. Only the hash and
the key leave the machine, and they go to VirusTotal only: redirects are not followed. There is no
upload path, so a file VirusTotal has never seen stays unknown.

Normalizer. `data.attributes.last_analysis_stats` (malicious, suspicious, harmless, undetected) is
mapped to at most one finding per file:

    5 or more engines say malicious   ext.virustotal.malicious    high
    1 to 4 engines say malicious      ext.virustotal.suspicious   medium (a few engines can be
    only "suspicious" engines         ext.virustotal.suspicious   medium  a false positive)
    no engine flags the file          no finding; counted as known to VirusTotal, never "clean"
    404, or no engine result at all   no finding; counted as unknown to VirusTotal

The mapping is fixed here and is never tuned from what VirusTotal returns (FD22). The public API
key allows 4 lookups a minute, so a scan makes at most 4 by default and never sleeps; a failed
call is not retried.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, ClassVar

from .. import net
from ..model import OWASP_SUPPLY_CHAIN, Evidence, Finding, Location
from .base import EXT_PREFIX, FileTarget, HashProvider, ProviderError

MALICIOUS_HIGH = 5  # engines; below this a detection may be one vendor's false positive
REPORT_URL = "https://www.virustotal.com/gui/file/"  # the public report, whatever base URL is called
_COUNTS = ("malicious", "suspicious", "harmless", "undetected")
_SHA256 = re.compile(r"[0-9a-f]{64}")


def _why(err: net.NetError) -> str:
    """Why a call failed, from fixed words only: nothing the server sent is repeated."""
    if err.status is not None:
        return f"HTTP {err.status}"
    text = str(err)
    if "invalid JSON" in text:
        return "unreadable answer"
    return "timed out" if "timed out" in text else "unreachable"


def _counts(doc: Any) -> dict[str, int] | None:
    try:
        raw = doc["data"]["attributes"]["last_analysis_stats"]
    except (KeyError, TypeError, IndexError):
        return None
    if not isinstance(raw, dict):
        return None
    out: dict[str, int] = {}
    for key in _COUNTS:
        value = raw.get(key, 0)
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            return None
        out[key] = value
    return out


@dataclass
class VirusTotal(HashProvider):
    name: ClassVar[str] = "virustotal"
    label: ClassVar[str] = "VirusTotal"
    default_base_url: ClassVar[str] = "https://www.virustotal.com"
    default_max_lookups: ClassVar[int] = 4  # the public API key allows 4 lookups a minute

    def lookup(self, sha256: str) -> dict[str, int] | None:
        """The engine counts for one hash; None when VirusTotal has no verdict on it."""
        sha = sha256.lower()
        if not _SHA256.fullmatch(sha):
            raise ProviderError("not a SHA-256")
        try:
            # one attempt, no sleep: a 429 is the quota, not a hiccup. 404 is an answer.
            resp = net.request("GET", f"{self.base_url}/api/v3/files/{sha}", headers={"x-apikey": self.key},
                               timeout=self.timeout, ok=(404,), retry_on=frozenset(), follow_redirects=False)
        except net.NetError as err:
            raise ProviderError(_why(err), err.status) from None
        if resp.status == 404:
            return None
        counts = _counts(resp.data)
        if counts is None:
            raise ProviderError("an answer without engine counts")
        return counts if sum(counts.values()) else None  # on record, but no engine has judged it

    def finding(self, target: FileTarget, answer: dict[str, int]) -> Finding | None:
        counts, sha = answer, str(target.sha256).lower()
        malicious, suspicious, total = counts["malicious"], counts["suspicious"], sum(counts.values())
        if malicious >= MALICIOUS_HIGH:
            # the verdict stays "suspicious": "malicious" is our own judgement, never a third party's
            rule, severity, verdict, confidence = "malicious", "high", "suspicious", 80
            said = f"{malicious} of {total} engines flag {target.name} as malicious"
        elif malicious:
            rule, severity, verdict, confidence = "suspicious", "medium", "suspicious", 40
            said = (f"{malicious} of {total} engines flag {target.name} as malicious "
                    "(a few engines can be a false positive)")
        elif suspicious:
            rule, severity, verdict, confidence = "suspicious", "medium", "suspicious", 30
            said = (f"{suspicious} of {total} engines flag {target.name} as suspicious, none as malicious "
                    "(can be a false positive)")
        else:
            return None
        link = REPORT_URL + sha
        detail = {"provider": self.label, "engines": dict(counts),
                  "severity_basis": f"{malicious} malicious, {suspicious} suspicious of {total} engines"}
        return Finding(
            rule_id=f"{EXT_PREFIX}{self.name}.{rule}",
            title=f"{self.label}: {said}",
            severity=severity,
            verdict=verdict,
            confidence=confidence,
            component=target.component,
            location=Location(target.location),
            evidence=[Evidence(self.name, sha, link, detail)],
            remediation=f"Read the {self.label} report before you load or install this file: {link} "
                        f"(this is {self.label}'s result, not an AIterprise judgement).",
            maps_to=[OWASP_SUPPLY_CHAIN],
            discriminator=sha,  # another file content at the same path is another finding
        )
