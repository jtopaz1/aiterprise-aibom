"""Minimal HTTP client (urllib) with the platform client obligations (design doc 13 §4.8).

- privacy-revealing values go in POST bodies, never in URLs;
- retry only 429/502/503, at most 3 times, exponential backoff with jitter, honouring Retry-After;
- a generic User-Agent (no user or machine identifiers);
- errors keep the RFC 9457 problem document, so callers can act on its `type`.
"""

from __future__ import annotations

import json
import random
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any

from . import __version__

USER_AGENT = f"aiterprise-scan/{__version__}"
RETRY_STATUSES = {429, 502, 503}
MAX_RETRIES = 3
MAX_RESPONSE_BYTES = 64 * 1024 * 1024
MAX_RETRY_AFTER = 60.0


class NetError(Exception):
    """A request that gave no usable answer. `kind` says why, so that no caller reads the message:

    http         the server answered with an error status (`status`, `problem`)
    redirect     a 3xx that the caller chose not to follow (`status`)
    timeout      no answer in time
    unreachable  no connection (DNS, refused, TLS, any other transport error)
    invalid      an answer that is not the JSON it should be
    too-large    an answer over the size limit
    refused      not sent at all (a download that is not over https)
    """

    def __init__(self, message: str, status: int | None = None, problem: dict | None = None,
                 headers: dict[str, str] | None = None, kind: str | None = None) -> None:
        super().__init__(message)
        self.status = status
        self.problem = problem or {}
        self.headers = headers or {}
        self.kind = kind or ("http" if status is not None else "unreachable")

    @property
    def problem_type(self) -> str:
        """The problem `type` suffix (e.g. `plan_required`), or ''."""
        t = str(self.problem.get("type") or "")
        return t.rsplit("/", 1)[-1].rsplit("#", 1)[-1] if t else ""


@dataclass
class Response:
    status: int
    headers: dict[str, str] = field(default_factory=dict)
    data: Any = None


def _retry_after(headers: dict[str, str]) -> float | None:
    value = headers.get("retry-after")
    if not value:
        return None
    try:
        return max(0.0, min(float(value), MAX_RETRY_AFTER))
    except ValueError:
        return None


def _lower(headers) -> dict[str, str]:
    return {k.lower(): v for k, v in (headers.items() if headers else [])}


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None  # the 3xx then surfaces as an HTTPError


_NO_REDIRECT = urllib.request.build_opener(_NoRedirect)


def _decode(raw: bytes, url: str) -> Any:
    if not raw:
        return None
    try:
        return json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as err:
        raise NetError(f"{url} returned invalid JSON: {err}", kind="invalid") from None


def _transport_kind(err: BaseException) -> str:
    reason = getattr(err, "reason", err)
    timed_out = isinstance(err, TimeoutError) or isinstance(reason, TimeoutError) or "timed out" in str(reason)
    return "timeout" if timed_out else "unreachable"


def request(
    method: str,
    url: str,
    body: Any | None = None,
    headers: dict[str, str] | None = None,
    timeout: float = 20.0,
    sleep=time.sleep,
    max_retries: int = MAX_RETRIES,
    ok: tuple[int, ...] = (),
    retry_on: frozenset[int] | set[int] = RETRY_STATUSES,
    raw: bool = False,
    follow_redirects: bool = True,
) -> Response:
    """One HTTP exchange with retries. Statuses in `ok` (e.g. 304) are returned, not raised.

    `raw=True` returns the body as bytes instead of decoding it as JSON (errors are still parsed
    as problem documents). `follow_redirects=False` raises on a 3xx instead of following it:
    urllib re-sends every request header to the new location, so a caller whose key must reach
    one host only turns redirects off."""
    opener = urllib.request.urlopen if follow_redirects else _NO_REDIRECT.open
    data = None
    hdrs = {"User-Agent": USER_AGENT, "Accept": "application/json"}
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        hdrs["Content-Type"] = "application/json"
    if headers:
        hdrs.update(headers)
    attempt = 0
    while True:
        req = urllib.request.Request(url, data=data, method=method, headers=hdrs)
        try:
            with opener(req, timeout=timeout) as resp:
                body_bytes = resp.read(MAX_RESPONSE_BYTES + 1)
                if len(body_bytes) > MAX_RESPONSE_BYTES:
                    raise NetError(f"response from {url} exceeds {MAX_RESPONSE_BYTES} bytes", kind="too-large")
                return Response(resp.status, _lower(resp.headers), body_bytes if raw else _decode(body_bytes, url))
        except urllib.error.HTTPError as err:
            rh = _lower(err.headers)
            if err.code in ok:
                return Response(err.code, rh, None)
            if err.code in retry_on and attempt < max_retries:
                delay = _retry_after(rh)
                if delay is None:
                    delay = (2**attempt) * 0.5 + random.uniform(0, 0.5)
                else:
                    delay += random.uniform(0, 0.5)  # jitter on top of Retry-After
                sleep(delay)
                attempt += 1
                continue
            try:
                err_body = err.read(64 * 1024)
                problem = json.loads(err_body.decode("utf-8")) if err_body else {}
            except (OSError, ValueError):
                problem = {}
            if not isinstance(problem, dict):
                problem = {}
            if not follow_redirects and 300 <= err.code < 400:
                raise NetError(f"{method} {url} -> HTTP {err.code} (a redirect, not followed)", status=err.code,
                               problem=problem, headers=rh, kind="redirect") from None
            raise NetError(f"{method} {url} -> HTTP {err.code}", status=err.code, problem=problem,
                           headers=rh) from None
        except (urllib.error.URLError, TimeoutError, OSError) as err:
            raise NetError(f"{method} {url} failed: {getattr(err, 'reason', err)}",
                           kind=_transport_kind(err)) from None


def download(url: str, max_bytes: int, timeout: float = 60.0) -> bytes:
    """GET raw bytes with no credential (bundle CDN). Raises NetError."""
    if not url.startswith("https://"):
        raise NetError(f"refusing a non-HTTPS download: {url}", kind="refused")
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read(max_bytes + 1)
    except urllib.error.HTTPError as err:
        raise NetError(f"GET {url.split('?', 1)[0]} -> HTTP {err.code}", status=err.code) from None
    except (urllib.error.URLError, TimeoutError, OSError) as err:
        raise NetError(f"GET {url.split('?', 1)[0]} failed: {getattr(err, 'reason', err)}",
                       kind=_transport_kind(err)) from None
    if len(raw) > max_bytes:
        raise NetError(f"{url.split('?', 1)[0]} exceeds {max_bytes} bytes", kind="too-large")
    return raw


def request_json(
    method: str,
    url: str,
    body: Any | None = None,
    headers: dict[str, str] | None = None,
    timeout: float = 20.0,
    sleep=time.sleep,
) -> Any:
    return request(method, url, body, headers, timeout, sleep).data
