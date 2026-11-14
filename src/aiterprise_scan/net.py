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
    def __init__(self, message: str, status: int | None = None, problem: dict | None = None,
                 headers: dict[str, str] | None = None) -> None:
        super().__init__(message)
        self.status = status
        self.problem = problem or {}
        self.headers = headers or {}

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


def _decode(raw: bytes, url: str) -> Any:
    if not raw:
        return None
    try:
        return json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as err:
        raise NetError(f"{url} returned invalid JSON: {err}") from None


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
) -> Response:
    """One HTTP exchange with retries. Statuses in `ok` (e.g. 304) are returned, not raised."""
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
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                raw = resp.read(MAX_RESPONSE_BYTES + 1)
                if len(raw) > MAX_RESPONSE_BYTES:
                    raise NetError(f"response from {url} exceeds {MAX_RESPONSE_BYTES} bytes")
                return Response(resp.status, _lower(resp.headers), _decode(raw, url))
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
                raw = err.read(64 * 1024)
                problem = json.loads(raw.decode("utf-8")) if raw else {}
            except (OSError, ValueError):
                problem = {}
            if not isinstance(problem, dict):
                problem = {}
            raise NetError(f"{method} {url} -> HTTP {err.code}", status=err.code, problem=problem,
                           headers=rh) from None
        except (urllib.error.URLError, TimeoutError, OSError) as err:
            raise NetError(f"{method} {url} failed: {getattr(err, 'reason', err)}") from None


def download(url: str, max_bytes: int, timeout: float = 60.0) -> bytes:
    """GET raw bytes with no credential (bundle CDN). Raises NetError."""
    if not url.startswith("https://"):
        raise NetError(f"refusing a non-HTTPS download: {url}")
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read(max_bytes + 1)
    except urllib.error.HTTPError as err:
        raise NetError(f"GET {url.split('?', 1)[0]} -> HTTP {err.code}", status=err.code) from None
    except (urllib.error.URLError, TimeoutError, OSError) as err:
        raise NetError(f"GET {url.split('?', 1)[0]} failed: {getattr(err, 'reason', err)}") from None
    if len(raw) > max_bytes:
        raise NetError(f"{url.split('?', 1)[0]} exceeds {max_bytes} bytes")
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
