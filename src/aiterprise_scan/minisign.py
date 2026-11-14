"""The minisign signature and public-key formats (https://jedisct1.github.io/minisign/).

Public key: `untrusted comment: …` then base64("Ed" ‖ key id (8 bytes) ‖ Ed25519 key (32 bytes)).
Signature:  `untrusted comment: …`, base64(algorithm ‖ key id ‖ signature (64 bytes)),
            `trusted comment: …`, base64(global signature over signature ‖ trusted comment).
Algorithm `ED` signs the BLAKE2b-512 hash of the file (minisign's default); `Ed` signs the file.
A key id prints as minisign prints it: the 8 bytes read as a little-endian integer, in upper-case hex.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
from dataclasses import dataclass

from . import ed25519

UNTRUSTED = "untrusted comment: "
TRUSTED = "trusted comment: "


class SignatureError(Exception):
    pass


def key_id_hex(key_id: bytes) -> str:
    return key_id[::-1].hex().upper()


def key_id_from_hex(text: str) -> bytes:
    raw = bytes.fromhex(text.strip())
    if len(raw) != 8:
        raise ValueError("a minisign key id is 8 bytes (16 hex digits)")
    return raw[::-1]


@dataclass(frozen=True)
class PublicKey:
    key_id: bytes
    key: bytes

    @property
    def key_id_hex(self) -> str:
        return key_id_hex(self.key_id)


@dataclass(frozen=True)
class Signature:
    algorithm: bytes
    key_id: bytes
    signature: bytes
    trusted_comment: str
    global_signature: bytes


def _b64(text: str, what: str) -> bytes:
    try:
        return base64.b64decode(text.strip(), validate=True)
    except (binascii.Error, ValueError):
        raise SignatureError(f"{what}: not valid base64") from None


def parse_public_key(text: str) -> PublicKey:
    lines = [ln.strip() for ln in text.strip().splitlines() if ln.strip()]
    if not lines:
        raise SignatureError("empty public key")
    line = lines[1] if lines[0].startswith(UNTRUSTED) and len(lines) > 1 else lines[0]
    raw = _b64(line, "public key")
    if len(raw) != 42 or raw[:2] != b"Ed":
        raise SignatureError("not a minisign Ed25519 public key")
    return PublicKey(raw[2:10], raw[10:])


def parse_signature(text: str) -> Signature:
    lines = text.replace("\r\n", "\n").split("\n")
    if len(lines) < 4 or not lines[0].startswith(UNTRUSTED) or not lines[2].startswith(TRUSTED):
        raise SignatureError("not a minisign signature (expected 4 lines)")
    raw = _b64(lines[1], "signature")
    if len(raw) != 74 or raw[:2] not in (b"ED", b"Ed"):
        raise SignatureError("unsupported minisign signature algorithm")
    glob = _b64(lines[3], "global signature")
    if len(glob) != 64:
        raise SignatureError("malformed global signature")
    return Signature(raw[:2], raw[2:10], raw[10:], lines[2][len(TRUSTED):], glob)


def verify(public: PublicKey, message: bytes, signature_text: str) -> str:
    """Verify `signature_text` over `message`; return the trusted comment. Raises SignatureError."""
    sig = parse_signature(signature_text)
    if sig.key_id != public.key_id:
        raise SignatureError(f"signed with key {key_id_hex(sig.key_id)}, expected key {public.key_id_hex}")
    data = hashlib.blake2b(message, digest_size=64).digest() if sig.algorithm == b"ED" else message
    if not ed25519.verify(public.key, data, sig.signature):
        raise SignatureError("signature does not match the file")
    if not ed25519.verify(public.key, sig.signature + sig.trusted_comment.encode("utf-8"), sig.global_signature):
        raise SignatureError("trusted comment was altered")
    return sig.trusted_comment


def sign(seed: bytes, key_id: bytes, message: bytes, trusted_comment: str,
         untrusted_comment: str = "signature from aiterprise-scan release tooling", prehash: bool = True) -> str:
    alg = b"ED" if prehash else b"Ed"
    data = hashlib.blake2b(message, digest_size=64).digest() if prehash else message
    sig = ed25519.sign(seed, data)
    glob = ed25519.sign(seed, sig + trusted_comment.encode("utf-8"))
    return (f"{UNTRUSTED}{untrusted_comment}\n{base64.b64encode(alg + key_id + sig).decode()}\n"
            f"{TRUSTED}{trusted_comment}\n{base64.b64encode(glob).decode()}\n")


def public_key_text(seed: bytes, key_id: bytes) -> str:
    raw = b"Ed" + key_id + ed25519.public_key(seed)
    return f"{UNTRUSTED}minisign public key {key_id_hex(key_id)}\n{base64.b64encode(raw).decode()}\n"
