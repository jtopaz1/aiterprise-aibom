"""The provider interface: what every BYO-key adapter is, and all the engine knows about one.

An adapter is one third-party file-reputation service called with the customer's own key. It is
given a SHA-256 and nothing else: it holds no cache handle, no SecDB client and no way to send
file content (design doc 13 FD22: hash lookups only; results are never stored, merged or tuned
from). `lookup` asks the provider, `finding` maps its answer into our Finding/evidence model.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, ClassVar, Mapping

from .. import cloudpolicy
from ..model import Component, Finding

# Rule ids of provider findings live outside `ait.`: `ext.<provider>.<what>`.
EXT_PREFIX = "ext."
# What may travel in an HTTP header value: visible ASCII, no spaces, no control characters.
_HEADER_SAFE = re.compile(r"[\x21-\x7e]{1,512}")


def provider_of(rule_id: str) -> str | None:
    """The provider a rule id belongs to (`ext.virustotal.malicious` -> `virustotal`), else None."""
    if not rule_id.startswith(EXT_PREFIX):
        return None
    return rule_id[len(EXT_PREFIX):].split(".", 1)[0] or None


def is_external(rule_id: Any) -> bool:
    """True for a finding that is a third party's result, not an AIterprise rule."""
    return isinstance(rule_id, str) and rule_id.startswith(EXT_PREFIX)


class ConfigError(ValueError):
    """A `--byo` value or a provider environment variable that cannot be used (exit 2).

    Messages never quote the `--byo` value or the key: a key pasted where the variable name
    belongs must not end up on the terminal or in a CI log."""


class ProviderError(Exception):
    """A lookup that produced no answer. `status` is the HTTP status, None when there was none
    (unreachable, timed out, an answer that could not be read). Adapters build the text from
    fixed words: it never holds the key or anything the server sent."""

    def __init__(self, message: str, status: int | None = None) -> None:
        super().__init__(message)
        self.status = status


@dataclass
class FileTarget:
    """One file the scan examined, to be looked up by hash."""

    name: str  # file name, for titles
    location: str  # root-relative path (`archive!member` inside an archive)
    sha256: str | None = None
    path: Path | None = None  # hashed on demand when the scan did not hash the file itself
    component: Component | None = None
    rank: tuple = ()  # sort key: most suspicious first

    def digest(self) -> str | None:
        if self.sha256 is None and self.path is not None:
            try:
                with open(self.path, "rb") as fh:
                    self.sha256 = hashlib.file_digest(fh, "sha256").hexdigest()
            except OSError:
                return None
        return self.sha256


@dataclass
class HashProvider:
    """Base of every adapter. Subclasses set the class attributes, `lookup` and `finding`."""

    key: str = field(repr=False)  # never printed, logged or stored
    base_url: str = ""
    max_lookups: int = 4
    timeout: float = 20.0

    name: ClassVar[str] = ""  # registry key, `examined` source, rule-id segment
    label: ClassVar[str] = ""  # the provider's name as people write it
    default_base_url: ClassVar[str] = ""
    default_max_lookups: ClassVar[int] = 4

    @classmethod
    def url_env(cls) -> str:
        return f"AITERPRISE_{cls.name.upper()}_URL"

    @classmethod
    def budget_env(cls) -> str:
        return f"AITERPRISE_{cls.name.upper()}_MAX_LOOKUPS"

    @classmethod
    def from_env(cls, key: str, environ: Mapping[str, str]) -> "HashProvider":
        """The adapter for this run: the key plus the optional base-URL and budget overrides."""
        if not _HEADER_SAFE.fullmatch(key):
            raise ConfigError(f"--byo {cls.name}: the key in that variable has spaces or control characters and "
                              "cannot be sent")
        base = cls.default_base_url
        override = environ.get(cls.url_env(), "").strip()
        if override:
            try:
                base = cloudpolicy.check_cloud_url(override, cls.label)
            except cloudpolicy.CloudURLError as err:
                raise ConfigError(f"{cls.url_env()}: {err}") from None
        budget = cls.default_max_lookups
        raw = environ.get(cls.budget_env(), "").strip()
        if raw:
            if not raw.isascii() or not raw.isdigit() or int(raw) < 1:
                raise ConfigError(f"{cls.budget_env()} must be a whole number of lookups per scan, 1 or more")
            budget = int(raw)
        return cls(key=key, base_url=base, max_lookups=budget)

    def lookup(self, sha256: str) -> Any | None:
        """The provider's answer for one hash, or None when it has no record of it (which is
        "unknown", never "clean"). Raises ProviderError when there is no answer at all."""
        raise NotImplementedError

    def finding(self, target: FileTarget, answer: Any) -> Finding | None:
        """Map an answer into a finding about `target`; None when the provider flags nothing."""
        raise NotImplementedError
