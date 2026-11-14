"""Minimal HTTP client (urllib) with the platform client obligations (design doc 13 §4.8).

- privacy-revealing values go in POST bodies, never in URLs;
- retry only 429/502/503, at most 3 times, exponential backoff with jitter, honouring Retry-After;
- a generic User-Agent (no user or machine identifiers).
"""

from __future__ import annotations

import json
import random
import time
import urllib.error
import urllib.request
from typing import Any

from . import __version__

USER_AGENT = f"aiterprise-scan/{__version__}"
RETRY_STATUSES = {429, 502, 503}
MAX_RETRIES = 3
MAX_RESPONSE_BYTES = 64 * 1024 * 1024


class NetError(Exception):
    def __init__(self, message: str, status: int | None = None) -> None:
        super().__init__(message)
        self.status = status


def _retry_after(err: urllib.error.HTTPError) -> float | None:
    value = err.headers.get("Retry-After") if err.headers else None
    if not value:
        return None
    try:
        return max(0.0, min(float(value), 60.0))
    except ValueError:
        return None


def request_json(
    method: str,
    url: str,
    body: Any | None = None,
    headers: dict[str, str] | None = None,
    timeout: float = 20.0,
    sleep=time.sleep,
) -> Any:
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
                if not raw:
                    return None
                return json.loads(raw.decode("utf-8"))
        except urllib.error.HTTPError as err:
            if err.code in RETRY_STATUSES and attempt < MAX_RETRIES:
                delay = _retry_after(err)
                if delay is None:
                    delay = (2**attempt) * 0.5 + random.uniform(0, 0.5)
                sleep(delay)
                attempt += 1
                continue
            raise NetError(f"{method} {url} -> HTTP {err.code}", status=err.code) from None
        except (urllib.error.URLError, TimeoutError, OSError) as err:
            raise NetError(f"{method} {url} failed: {getattr(err, 'reason', err)}") from None
        except json.JSONDecodeError as err:
            raise NetError(f"{method} {url} returned invalid JSON: {err}") from None
