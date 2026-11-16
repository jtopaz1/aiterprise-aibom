"""`aiterprise-scan policy pull`: the organisation's policy from an AIterprise cloud (design doc 13 §9.7).

`GET <cloud>/api/policy/pull` with the SecDB API key returns the org policy as YAML with an ETag
(`"policy-v<N>"`). The file is written with a first-line comment naming that version, so the next
pull sends `If-None-Match` and an unchanged policy is not rewritten. A policy that does not load
with this scanner's own loader is refused and the local file is kept.

The cloud URL comes from `--cloud` or `AITERPRISE_CLOUD_URL`. A key is only ever sent over HTTPS —
plain HTTP is allowed to this machine (local development) and refused everywhere else; the same
guard applies to `upload --cloud`.
"""

from __future__ import annotations

import os
import re
import sys
from pathlib import Path
from typing import Callable
from urllib.parse import urlsplit

from . import TOOL_NAME, credentials, net, policy

CLOUD_ENV = "AITERPRISE_CLOUD_URL"
PULL_PATH = "/api/policy/pull"
MAX_POLICY_BYTES = 256 * 1024
LOOPBACK = {"127.0.0.1", "localhost", "::1"}
_HEADER = re.compile(r'^# .*?ETag (?P<etag>"[^"]*")')


class CloudURLError(ValueError):
    pass


def check_cloud_url(url: str, what: str = "cloud") -> str:
    """The base URL without a trailing slash, or CloudURLError if a key must not go there.

    `what` names the destination in the messages: the BYO-key providers reuse this guard for their
    base-URL override, so there is one rule for every place a key is sent."""
    parts = urlsplit(url.strip())
    host = (parts.hostname or "").lower()
    if parts.username or parts.password:  # checked first: a URL holding credentials is never echoed
        hint = "; log in with `aiterprise-scan login`" if what == "cloud" else ""
        raise CloudURLError(f"put no credentials in the {what} URL{hint}")
    if not host or parts.scheme not in ("https", "http"):
        raise CloudURLError(f"not a {what} URL: {url!r} (expected https://host)")
    if parts.scheme == "http" and host not in LOOPBACK:
        raise CloudURLError(f"refusing to send an API key over plain http to {host}; use https://")
    return url.strip().rstrip("/")


def cloud_url(explicit: str | None) -> str | None:
    value = explicit or os.environ.get(CLOUD_ENV)
    return check_cloud_url(value) if value else None


def _fetch(url: str, headers: dict) -> net.Response:
    # no redirect is followed: urllib would send the Authorization header on to the new address
    return net.request("GET", url, headers=headers, timeout=20.0, ok=(304,), retry_on={502, 503}, raw=True,
                       follow_redirects=False)


TRANSPORT: Callable[[str, dict], net.Response] = _fetch


def _err(msg: str) -> int:
    print(f"{TOOL_NAME}: error: {msg}", file=sys.stderr)
    return 2


def _local_etag(path: Path) -> str | None:
    try:
        with path.open(encoding="utf-8") as fh:
            first = fh.readline()
    except (OSError, UnicodeDecodeError):
        return None
    m = _HEADER.match(first)
    return m.group("etag") if m else None


def _explain(err: net.NetError) -> str:
    detail = str(err.problem.get("detail") or err.problem.get("title") or "")
    if err.status is None:
        return f"cloud unreachable: {err}"
    if err.kind == "redirect":
        return (f"the cloud answered with a redirect (HTTP {err.status}), which is not followed: a request that "
                "carries your key goes to one address only; use the cloud's final address")
    if err.status == 404:
        return "no org policy has been published on the cloud yet (Policy page in the dashboard)"
    if err.problem_type == "plan_required":
        return f"{detail or 'org policy sync needs a higher plan'}"
    if err.status in (401, 403):
        return f"the cloud refused this key ({err.status} {err.problem_type or ''}){': ' + detail if detail else ''}"
    return f"cloud error {err.status} {err.problem_type}{': ' + detail if detail else ''}"


def cmd_pull(cloud: str | None, out: Path) -> int:
    try:
        base = cloud_url(cloud)
    except CloudURLError as err:
        return _err(str(err))
    if base is None:
        return _err(f"policy pull needs the cloud URL: --cloud https://… or set {CLOUD_ENV}")
    cred = credentials.load()
    if cred is None:
        return _err("not logged in (run `aiterprise-scan login`, or set AITERPRISE_API_KEY)")
    headers = {"Authorization": f"Bearer {cred.secret}", "Accept": "application/yaml"}
    etag = _local_etag(out) if out.exists() else None
    if etag:
        headers["If-None-Match"] = etag
    try:
        resp = TRANSPORT(base + PULL_PATH, headers)
    except net.NetError as err:
        return _err(_explain(err))
    version = resp.headers.get("x-aibom-policy-version", "?")
    if resp.status == 304:
        print(f"org policy v{version} is up to date ({out})")
        return 0
    body = resp.data if isinstance(resp.data, bytes) else b""
    if len(body) > MAX_POLICY_BYTES:
        return _err(f"the org policy is larger than {MAX_POLICY_BYTES // 1024} KiB; refusing it")
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError:
        return _err("the org policy is not UTF-8; the local file was kept")
    pol = policy.loads_policy(text, f"{base}{PULL_PATH}")
    if pol.errors:
        return _err("the org policy does not load with this scanner, the local file was kept: "
                    + "; ".join(pol.errors))
    new_etag = resp.headers.get("etag") or f'"policy-v{version}"'
    header = (f"# aiterprise-scan policy pull · org policy version {version} · ETag {new_etag} · "
              f"from {urlsplit(base).hostname}\n"
              "# Edit the org policy in the cloud dashboard; the next pull replaces this file.\n")
    out.parent.mkdir(parents=True, exist_ok=True)
    tmp = out.with_name(out.name + ".tmp")
    tmp.write_text(header + text, encoding="utf-8", newline="\n")
    os.replace(tmp, out)
    print(f"org policy v{version} written to {out}")
    for w in pol.warnings:
        print(f"warning: {w}")
    return 0
