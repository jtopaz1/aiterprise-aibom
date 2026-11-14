"""Tests for the secrets analyzer (C32)."""

import os
import tempfile
import unittest
from pathlib import Path

from aiterprise_scan import secrets
from aiterprise_scan.model import OWASP_SENSITIVE_INFO, ScanResult
from aiterprise_scan.walk import walk

# Non-placeholder character pool (no 'abcdef'/'123456', no long repeats).
POOL = "qRsTuVwXyZ4KpM8NvW2JtH6LgQ9BdF3K7PxMzNvTqWyLd" * 4
UPOOL = "QRSTUVWXYZ4KPM8NVW2JTH6LGQ9BDF3K7PXMZ"


def tok(prefix: str, n: int, upper: bool = False) -> str:
    return prefix + (UPOOL * 2 if upper else POOL)[:n]


class RedactTests(unittest.TestCase):
    def test_redact_hides_middle(self):
        v = tok("sk-proj-", 40)
        r = secrets.redact(v)
        self.assertNotEqual(r, v)
        self.assertNotIn(v[8:-4], r)
        self.assertTrue(r.startswith("sk-p"))
        self.assertLess(len(r), len(v) + 1)

    def test_redact_short(self):
        self.assertNotIn("abcd", secrets.redact("abcd"))

    def test_redact_pem_header_only(self):
        r = secrets.redact("-----BEGIN RSA PRIVATE KEY-----\nMIIabc\n-----END")
        self.assertEqual(r, "-----BEGIN RSA PRIVATE KEY-----")


class FindSecretsTests(unittest.TestCase):
    def test_each_kind_detected(self):
        cases = {
            "anthropic": tok("sk-ant-api03-", 50),
            "openai": tok("sk-proj-", 40),
            "huggingface": tok("hf_", 34),
            "github": tok("ghp_", 36),
            "xai": tok("xai-", 40),
            "groq": tok("gsk_", 52),
            "replicate": tok("r8_", 40),
            "aws": tok("AKIA", 16, upper=True),
            "google": tok("AIza", 35),
            "slack": "xoxb-" + POOL[:24],
        }
        for expected, value in cases.items():
            with self.subTest(kind=expected):
                matches = secrets.find_secrets(f"key = {value}")
                kinds = {m.kind for m in matches}
                self.assertIn(expected, kinds, f"{expected} not detected in {value!r}")

    def test_openai_legacy(self):
        v = "sk-" + POOL[:48]
        self.assertTrue(any(m.kind == "openai" for m in secrets.find_secrets(v)))

    def test_pem_detected(self):
        for header in ("-----BEGIN RSA PRIVATE KEY-----",
                       "-----BEGIN OPENSSH PRIVATE KEY-----",
                       "-----BEGIN PRIVATE KEY-----"):
            self.assertTrue(secrets.find_secrets(header), header)

    def test_placeholders_rejected(self):
        placeholders = [
            "sk-...",
            "sk-proj-${OPENAI_API_KEY}",
            "sk-ant-api03-your-api-key-here-please-change",
            "hf_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
            "AKIAIOSFODNN7EXAMPLE",
            "sk-proj-" + "a" * 40,
            "<your-anthropic-key>",
            "ghp_changeme_changeme_changeme_change",
        ]
        for p in placeholders:
            with self.subTest(p=p):
                self.assertEqual(secrets.find_secrets(p), [],
                                 f"placeholder wrongly matched: {p!r}")

    def test_line_numbers(self):
        text = "line1\nline2\nkey = " + tok("sk-proj-", 40) + "\n"
        matches = secrets.find_secrets(text)
        self.assertEqual(matches[0].line, 3)

    def test_distinct_digests(self):
        a = tok("sk-proj-", 40)
        b = tok("hf_", 34)
        matches = secrets.find_secrets(f"{a}\n{b}")
        digests = {m.digest for m in matches}
        self.assertEqual(len(digests), 2)

    def test_raw_value_never_exposed(self):
        v = tok("sk-ant-api03-", 50)
        for m in secrets.find_secrets(v):
            self.assertNotIn(v, m.redacted)
            self.assertNotIn(v, m.digest)
            self.assertNotEqual(m.redacted, v)

    def test_redact_secrets_in_text(self):
        v = tok("hf_", 34)
        out = secrets.redact_secrets_in(f"use {v} now")
        self.assertNotIn(v, out)
        self.assertIn("now", out)


class ScanSecretsTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name).resolve()

    def tearDown(self):
        self.tmp.cleanup()

    def _write(self, rel, content, *, binary=None):
        p = self.root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        if binary is not None:
            p.write_bytes(binary)
        else:
            p.write_text(content, encoding="utf-8")
        return p

    def test_env_file_flagged_high(self):
        key = tok("sk-ant-api03-", 50)
        self._write(".env", f"ANTHROPIC_API_KEY={key}\n")
        findings = secrets.scan_secrets(self.root, walk(self.root, all_files=True))
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f.severity, "high")
        self.assertEqual(f.verdict, "suspicious")
        self.assertEqual(f.rule_id, "ait.secret.anthropic")
        self.assertIn(OWASP_SENSITIVE_INFO, f.maps_to)
        self.assertTrue(f.discriminator)
        # redacted present; raw never present anywhere
        blob = str(f.to_dict())
        self.assertNotIn(key, blob)

    def test_lockfiles_and_models_skipped(self):
        key = tok("sk-proj-", 40)
        self._write("package-lock.json", f'{{"k":"{key}"}}')
        self._write("model.safetensors", "", binary=key.encode())
        self._write("app.min.js", f'var k="{key}"')
        findings = secrets.scan_secrets(self.root, walk(self.root, all_files=True))
        self.assertEqual(findings, [])

    def test_large_file_skipped_and_reported(self):
        key = tok("sk-proj-", 40)
        padding = "x" * (secrets.MAX_SECRET_BYTES + 1000)
        self._write("big.env", key + "\n" + padding)
        result = ScanResult("t", "offline")
        findings = secrets.scan_secrets(self.root, walk(self.root, all_files=True), result)
        self.assertEqual(findings, [])
        self.assertTrue(any("big.env" in n and "not scanned" in n for n in result.notes))

    def test_two_secrets_two_findings(self):
        self._write("config.yaml", f"a: {tok('sk-proj-', 40)}\nb: {tok('hf_', 34)}\n")
        findings = secrets.scan_secrets(self.root, walk(self.root, all_files=True))
        self.assertEqual(len(findings), 2)
        self.assertEqual(len({f.fingerprint for f in findings}), 2)


if __name__ == "__main__":
    unittest.main()
