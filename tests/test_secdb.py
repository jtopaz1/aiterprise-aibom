"""SecDB API v1 client, credentials and scan enrichment — all against a fake transport (no network)."""

import contextlib
import hashlib
import io
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from aiterprise_scan import account, cli, credentials, net, secdb
from aiterprise_scan.model import Component, Location, ScanResult

KEY = "aik_live_" + "A" * 36
ME_FREE = {"credential": "api_key", "tenant_id": "t-1", "plan": "free", "packs": [], "channels": ["community-delayed"],
           "default_channel": "community-delayed", "scopes": ["lookup:read", "feedback:write"], "operations": None,
           "limits": {"lookups_per_minute": 4, "lookups_per_day": 1000, "lookups_per_month": 1000,
                      "ceiling_per_month": 1000, "prefix_checks_per_day": 50000}}
NOTICE = {"id": "ntc_gpl", "text": "Hash data from ClamAV (GPL-2.0) consensus.", "url": "https://example.test/n"}


def lookup_result(kind, value, verdict="unknown", **extra):
    return {"query": {"kind": kind, "value": value, "normalized": value}, "verdict": verdict,
            "confidence": None if verdict == "unknown" else 90, "categories": extra.pop("categories", []),
            "examined": {"sources": 5, "with_data": 0 if verdict == "unknown" else 1},
            "provenance": extra.pop("provenance", []), "allowlist_hits": [], "notices": extra.pop("notices", []),
            "channel": "community-delayed", "release": "rel_" + "0" * 64,
            "note": "unknown means no source holds data; it is not a statement of safety", **extra}


class FakeSecDB:
    """Routes (method, path) to handlers; records every request."""

    def __init__(self, routes):
        self.routes = routes
        self.calls = []

    def __call__(self, method, url, body, headers):
        path = url.split("secdb.test", 1)[1]
        self.calls.append((method, path, body, dict(headers)))
        handler = self.routes.get((method, path.split("?", 1)[0]))
        if handler is None:
            raise net.NetError(f"{method} {url} -> HTTP 404", 404,
                               {"type": "https://api.aiterprise.net/problems/not_found", "title": "Not found",
                                "status": 404})
        out = handler(body) if callable(handler) else handler
        if isinstance(out, Exception):
            raise out
        status, data = out if isinstance(out, tuple) else (200, out)
        return net.Response(status, {}, data)


def problem(status, ptype, title="x"):
    return net.NetError(f"HTTP {status}", status, {"type": f"https://api.aiterprise.net/problems/{ptype}",
                                                    "title": title, "status": status, "request_id": "req_1"})


def client(routes, cred=None):
    fake = FakeSecDB(routes)
    c = secdb.Client(cred or credentials.Credential("api_key", KEY, "env"), base_url="https://secdb.test",
                     transport=fake, sleep=lambda s: None)
    return c, fake


class CredentialTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.env = mock.patch.dict(os.environ, {"AITERPRISE_HOME": self.tmp.name}, clear=False)
        self.env.start()
        os.environ.pop("AITERPRISE_API_KEY", None)

    def tearDown(self):
        self.env.stop()
        self.tmp.cleanup()

    def test_mask_never_shows_the_secret(self):
        masked = credentials.mask(KEY)
        self.assertTrue(masked.startswith("aik_live_"))
        self.assertNotIn("A" * 8, masked)

    def test_env_beats_stored_key_beats_install_token(self):
        credentials.save_install("ait_" + "b" * 40, "inst_1", "community-delayed")
        self.assertEqual(credentials.load().kind, "install_token")
        credentials.save_api_key(KEY)
        self.assertEqual((credentials.load().kind, credentials.load().origin), ("api_key", "stored"))
        with mock.patch.dict(os.environ, {"AITERPRISE_API_KEY": "aik_live_" + "C" * 36}):
            self.assertEqual(credentials.load().origin, "env")

    def test_stored_key_is_not_plain_text_on_windows(self):
        credentials.save_api_key(KEY)
        raw = (Path(self.tmp.name) / "credentials.json").read_bytes()
        if sys.platform == "win32":
            self.assertNotIn(KEY.encode(), raw)
        self.assertEqual(credentials.load().secret, KEY)

    def test_clear(self):
        credentials.save_api_key(KEY)
        credentials.clear()
        self.assertIsNone(credentials.load())


class ClientTests(unittest.TestCase):
    def test_me(self):
        c, fake = client({("GET", "/v1/me"): ME_FREE})
        me = c.me()
        self.assertEqual((me["plan"], me["limits"]["lookups_per_minute"]), ("free", 4))
        self.assertEqual(fake.calls[0][3]["Authorization"], f"Bearer {KEY}")

    def test_problem_type_is_exposed(self):
        c, _ = client({("POST", "/v1/aibom/scans"): problem(403, "plan_required", "Pro plan required")})
        with self.assertRaises(secdb.SecDBError) as ctx:
            c.upload_scan("demo", {"findings": []}, "2026-11-14T00:00:00Z")
        self.assertEqual((ctx.exception.status, ctx.exception.type), (403, "plan_required"))
        self.assertIn("Pro plan required", str(ctx.exception))

    def test_metered_posts_carry_an_idempotency_key_and_values_ride_in_the_body(self):
        c, fake = client({("POST", "/v1/lookup"): lambda b: lookup_result(b["kind"], b["value"])})
        c.lookup("package", "pkg:pypi/litellm@1.82.7")
        method, path, body, headers = fake.calls[0]
        self.assertEqual((method, path), ("POST", "/v1/lookup"))
        self.assertNotIn("litellm", path)
        self.assertEqual(body, {"kind": "package", "value": "pkg:pypi/litellm@1.82.7"})
        self.assertTrue(headers.get("Idempotency-Key"))

    def test_upload_body_shape(self):
        seen = {}

        def accept(body):
            seen.update(body)
            return 201, {"scan_id": "scan_01", "project": body["project"], "received_at": "2026-11-14T00:00:00Z",
                         "status": "stored", "findings_new": 0}

        c, _ = client({("POST", "/v1/aibom/scans"): accept})
        out = c.upload_scan("demo", {"findings": []}, "2026-11-14T00:00:00Z")
        self.assertEqual(out["scan_id"], "scan_01")
        self.assertEqual(set(seen), {"project", "scanner_version", "scanned_at", "format", "document"})
        self.assertEqual(seen["format"], "aiterprise-json")

    def test_report_has_a_consent_record(self):
        seen = {}
        c, _ = client({("POST", "/v1/reports"): lambda b: (seen.update(b) or (202, {"report_id": "rpt_1",
                                                                                  "status": "received"}))})
        c.report("false_positive", rule_id="ait.pkg.typosquat", notes="fingerprint 0123456789abcdef")
        self.assertEqual(seen["type"], "false_positive")
        self.assertEqual(seen["consent"]["basis"], "user_consent")
        self.assertTrue(seen["consent"]["given_at"].endswith("Z"))


def model_file(sha):
    return Component("model.pt", ctype="model-file", locations=[Location("model.pt")], hashes={"sha256": sha},
                     source="file", properties={"path": "model.pt"})


def pkg(name, version, eco="pypi", ai=True):
    c = Component(name, ecosystem=eco, version=version, locations=[Location("requirements.txt", 1)],
                  source="lockfile")
    c.ai = ai
    return c


class EnrichTests(unittest.TestCase):
    def test_known_bad_model_hash(self):
        sha = "ab" * 32
        routes = {("GET", "/v1/me"): ME_FREE,
                  ("POST", "/v1/verdict/file"): lambda b: dict(
                      lookup_result("sha256", b["hash"], "malicious", family="Pickle.Trojan", notices=[NOTICE],
                                    provenance=[{"source": "clamav", "name": "ClamAV", "licence": "ORCHESTRATE_ONLY",
                                                 "public_display": True}]),
                      hashes={"sha256": b["hash"]}, aliases=[], engines=[])}
        c, _ = client(routes)
        result = ScanResult("t", "online")
        fs = secdb.enrich([model_file(sha)], result, c)
        self.assertEqual([(f.rule_id, f.severity, f.verdict) for f in fs],
                         [("ait.model.hash.malicious", "high", "malicious")])
        self.assertEqual(fs[0].evidence[0].source, "secdb")
        self.assertEqual(result.notices, [NOTICE])
        ex = result.examined["secdb"]
        self.assertEqual((ex.checked, ex.with_data), (1, 1))

    def test_unknown_is_counted_never_called_safe(self):
        routes = {("GET", "/v1/me"): ME_FREE,
                  ("POST", "/v1/lookup"): lambda b: lookup_result(b["kind"], b["value"])}
        c, _ = client(routes)
        result = ScanResult("t", "online")
        self.assertEqual(secdb.enrich([pkg("openai", "1.50.0")], result, c), [])
        self.assertEqual((result.examined["secdb"].checked, result.examined["secdb"].with_data), (1, 0))

    def test_suspicious_package(self):
        routes = {("GET", "/v1/me"): ME_FREE,
                  ("POST", "/v1/lookup"): lambda b: lookup_result(b["kind"], b["value"], "suspicious",
                                                                  categories=["typosquat"])}
        c, _ = client(routes)
        fs = secdb.enrich([pkg("langchian", "0.1.0")], ScanResult("t", "online"), c)
        self.assertEqual([(f.rule_id, f.severity) for f in fs], [("ait.pkg.secdb.suspicious", "high")])

    def test_budget_follows_the_per_minute_limit(self):
        me = json.loads(json.dumps(ME_FREE))
        me["limits"]["lookups_per_minute"] = 2
        routes = {("GET", "/v1/me"): me, ("POST", "/v1/lookup"): lambda b: lookup_result(b["kind"], b["value"])}
        c, fake = client(routes)
        result = ScanResult("t", "online")
        secdb.enrich([pkg("a-pkg", "1.0"), pkg("b-pkg", "1.0"), pkg("c-pkg", "1.0")], result, c)
        self.assertEqual(sum(1 for call in fake.calls if call[1] == "/v1/lookup"), 2)
        self.assertTrue(any("1 item" in n and "UNVERIFIED" in n for n in result.notes), result.notes)
        self.assertEqual(result.examined["secdb"].errors, 0)

    def test_quota_exhausted_degrades_without_failing_the_scan(self):
        routes = {("GET", "/v1/me"): ME_FREE,
                  ("POST", "/v1/lookup"): problem(429, "quota-exceeded")}
        c, _ = client(routes)
        result = ScanResult("t", "online")
        self.assertEqual(secdb.enrich([pkg("a-pkg", "1.0")], result, c), [])
        self.assertEqual(result.examined["secdb"].errors, 0)
        self.assertTrue(any("quota" in n and "UNVERIFIED" in n for n in result.notes), result.notes)

    def test_outage_is_an_error(self):
        routes = {("GET", "/v1/me"): ME_FREE, ("POST", "/v1/lookup"): net.NetError("connection refused")}
        c, _ = client(routes)
        result = ScanResult("t", "online")
        secdb.enrich([pkg("a-pkg", "1.0")], result, c)
        self.assertEqual(result.examined["secdb"].errors, 1)

    def test_remote_mcp_url_is_checked_by_hash_prefix_only(self):
        url = "https://mcp.internal.example/sse"
        digest = hashlib.sha256(url.encode()).hexdigest()
        server = Component("internal", ctype="mcp-server", locations=[Location(".mcp.json", 3)], source="config",
                           properties={"url": url})

        def prefixes(body):
            self.assertEqual(body["space"], "mcp")
            self.assertTrue(all(len(p) == 8 for p in body["prefixes"]))
            return {"space": "mcp", "buckets": [{"prefix": digest[:8], "hashes": [
                {"sha256": digest, "verdict": "malicious", "categories": ["exfil"], "confidence": 90,
                 "specificity": "exact"}]}], "notices": [], "channel": "community-delayed",
                    "release": "rel_" + "0" * 64, "cache_ttl_seconds": 3600}

        c, fake = client({("GET", "/v1/me"): ME_FREE, ("POST", "/v1/lookup/prefixes"): prefixes})
        fs = secdb.enrich([server], ScanResult("t", "online"), c)
        self.assertEqual([f.rule_id for f in fs], ["ait.mcp.secdb.malicious"])
        sent = json.dumps([call[2] for call in fake.calls])
        self.assertNotIn("mcp.internal.example", sent)
        self.assertNotIn(digest, sent)


class CliTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.env = mock.patch.dict(os.environ, {"AITERPRISE_HOME": self.tmp.name})
        self.env.start()
        os.environ.pop("AITERPRISE_API_KEY", None)

    def tearDown(self):
        self.env.stop()
        self.tmp.cleanup()

    def run_cli(self, argv, stdin=""):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err), \
                mock.patch("sys.stdin", io.StringIO(stdin)):
            code = cli.main(argv)
        return code, out.getvalue(), err.getvalue()

    def test_login_status_logout(self):
        fake = FakeSecDB({("GET", "/v1/me"): ME_FREE,
                          ("GET", "/v1/usage"): {"period_start": "2026-11-01T00:00:00Z",
                                                 "period_end": "2026-12-01T00:00:00Z", "plan": "free",
                                                 "meters": [{"meter": "lookup", "used": 3, "included": 1000,
                                                             "ceiling": 1000}]}})
        with mock.patch.object(secdb, "DEFAULT_TRANSPORT", fake), \
                mock.patch.object(secdb, "base_url", return_value="https://secdb.test"):
            code, out, _ = self.run_cli(["login", "--key-stdin"], stdin=KEY + "\n")
            self.assertEqual(code, 0, out)
            self.assertIn("free", out)
            self.assertNotIn(KEY, out)
            code, out, _ = self.run_cli(["status"])
            self.assertEqual(code, 0)
            self.assertIn("lookup", out)
            self.assertIn("aik_live_", out)
            self.assertNotIn(KEY, out)
        self.assertEqual(self.run_cli(["logout"])[0], 0)
        self.assertIsNone(credentials.load())

    def test_upload_on_a_free_plan_explains_the_plan(self):
        report = Path(self.tmp.name) / "report.json"
        report.write_text(json.dumps({"target": "/w/demo", "started_at": "2026-11-14T00:00:00Z", "findings": []}),
                          encoding="utf-8")
        fake = FakeSecDB({("POST", "/v1/aibom/scans"): problem(403, "plan_required", "Plan required")})
        with mock.patch.dict(os.environ, {"AITERPRISE_API_KEY": KEY}), \
                mock.patch.object(secdb, "DEFAULT_TRANSPORT", fake), \
                mock.patch.object(secdb, "base_url", return_value="https://secdb.test"):
            code, _, err = self.run_cli(["upload", str(report)])
        self.assertEqual(code, 2)
        self.assertIn("Pro plan", err)
        body = fake.calls[-1][2]
        self.assertEqual(body["project"], "demo")
        self.assertEqual(body["scanned_at"], "2026-11-14T00:00:00Z")

    def test_upload_sends_no_local_paths(self):
        doc = {"target": "C:\\Users\\someone\\work\\demo-repo", "findings": [],
               "components": [{"name": "x", "locations": ["C:\\Users\\someone\\.cursor\\mcp.json", "requirements.txt"]}]}
        sent = account.upload_view(doc)
        self.assertEqual(sent["target"], "demo-repo")
        self.assertEqual(sent["components"][0]["locations"], ["~/.cursor/mcp.json", "requirements.txt"])
        self.assertNotIn("someone", json.dumps(sent))
        self.assertEqual(doc["target"], "C:\\Users\\someone\\work\\demo-repo")  # the caller's copy is untouched

    def test_login_with_a_bad_key_stores_nothing(self):
        fake = FakeSecDB({("GET", "/v1/me"): problem(401, "unauthorized", "Unauthorized")})
        with mock.patch.object(secdb, "DEFAULT_TRANSPORT", fake), \
                mock.patch.object(secdb, "base_url", return_value="https://secdb.test"):
            code, _, err = self.run_cli(["login", "--key-stdin"], stdin=KEY + "\n")
        self.assertEqual(code, 2)
        self.assertIn("unauthorized", err)
        self.assertIsNone(credentials.load())


if __name__ == "__main__":
    unittest.main()
