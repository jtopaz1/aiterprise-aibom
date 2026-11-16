"""BYO-key third-party enrichment (VirusTotal) against a local stub HTTP server; no real network.

The key used here is an obviously fake value. Every test that makes a call points the adapter at
the stub through AITERPRISE_VIRUSTOTAL_URL (plain http is allowed to this machine only).
"""

import ast
import contextlib
import hashlib
import http.server
import io
import json
import os
import pickle
import re
import tempfile
import threading
import time
import unittest
import zipfile
from pathlib import Path
from unittest import mock

from aiterprise_scan import cli, credentials, net, providers, secdb
from aiterprise_scan.cache import Cache
from aiterprise_scan.model import Component, Finding, Location, ScanResult
from aiterprise_scan.providers import FileTarget, ProviderError
from aiterprise_scan.providers.virustotal import VirusTotal

KEY = "fake-vt-key-" + "ab12" * 13  # not a real credential
ENV = "VT_TEST_KEY"


def run_cli(argv, env=None):
    """cli.main with captured stdout/stderr and a controlled environment."""
    out, err = io.StringIO(), io.StringIO()
    with mock.patch.dict(os.environ, env or {}), contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = cli.main(argv)
    return code, out.getvalue(), err.getvalue()


class ByoConfigTests(unittest.TestCase):
    def test_the_value_names_an_environment_variable_that_holds_the_key(self):
        (vt,) = providers.from_specs([f"virustotal={ENV}"], {ENV: KEY})
        self.assertEqual((vt.name, vt.label, vt.key), ("virustotal", "VirusTotal", KEY))
        self.assertEqual((vt.base_url, vt.max_lookups), ("https://www.virustotal.com", 4))

    def test_the_key_is_not_in_the_provider_repr(self):
        (vt,) = providers.from_specs([f"virustotal={ENV}"], {ENV: KEY})
        self.assertNotIn(KEY, repr(vt))

    def test_an_unknown_provider_is_a_usage_error(self):
        with self.assertRaises(providers.ConfigError) as ctx:
            providers.from_specs([f"nosuchprovider={ENV}"], {ENV: KEY})
        self.assertIn("virustotal", str(ctx.exception))  # names what is available

    def test_a_value_without_name_and_variable_is_a_usage_error(self):
        for spec in ("virustotal", "virustotal=", "=VT_TEST_KEY", ""):
            with self.subTest(spec=spec), self.assertRaises(providers.ConfigError):
                providers.from_specs([spec], {ENV: KEY})

    def test_an_unset_or_empty_variable_is_a_usage_error(self):
        for environ in ({}, {ENV: ""}, {ENV: "   "}):
            with self.subTest(environ=environ), self.assertRaises(providers.ConfigError):
                providers.from_specs([f"virustotal={ENV}"], environ)

    def test_a_key_given_instead_of_a_variable_name_is_never_echoed(self):
        # the user pasted the key where the variable name belongs, on either side of '='
        for spec in (f"virustotal={KEY}", f"{KEY}=virustotal", KEY):
            with self.subTest(spec=spec), self.assertRaises(providers.ConfigError) as ctx:
                providers.from_specs([spec], {})
            self.assertNotIn(KEY, str(ctx.exception))

    def test_a_key_that_cannot_travel_in_a_header_is_refused_without_echo(self):
        bad = KEY + "\r\nx-injected: 1"
        with self.assertRaises(providers.ConfigError) as ctx:
            providers.from_specs([f"virustotal={ENV}"], {ENV: bad})
        self.assertNotIn(KEY, str(ctx.exception))

    def test_the_same_provider_twice_is_a_usage_error(self):
        with self.assertRaises(providers.ConfigError):
            providers.from_specs([f"virustotal={ENV}", f"virustotal={ENV}"], {ENV: KEY})

    def test_base_url_override_follows_the_key_over_https_rule(self):
        ok = {ENV: KEY, "AITERPRISE_VIRUSTOTAL_URL": "http://127.0.0.1:8080/"}
        self.assertEqual(providers.from_specs([f"virustotal={ENV}"], ok)[0].base_url, "http://127.0.0.1:8080")
        proxy = {ENV: KEY, "AITERPRISE_VIRUSTOTAL_URL": "https://vt-proxy.example.com"}
        self.assertEqual(providers.from_specs([f"virustotal={ENV}"], proxy)[0].base_url, "https://vt-proxy.example.com")
        for url in ("http://vt-proxy.example.com", "ftp://127.0.0.1", "https://user:pw@vt-proxy.example.com"):
            with self.subTest(url=url), self.assertRaises(providers.ConfigError) as ctx:
                providers.from_specs([f"virustotal={ENV}"], {ENV: KEY, "AITERPRISE_VIRUSTOTAL_URL": url})
            self.assertIn("AITERPRISE_VIRUSTOTAL_URL", str(ctx.exception))

    def test_lookup_budget_override_must_be_a_positive_integer(self):
        env = {ENV: KEY, "AITERPRISE_VIRUSTOTAL_MAX_LOOKUPS": "25"}
        self.assertEqual(providers.from_specs([f"virustotal={ENV}"], env)[0].max_lookups, 25)
        for bad in ("0", "-3", "many", "4.5"):
            with self.subTest(bad=bad), self.assertRaises(providers.ConfigError) as ctx:
                providers.from_specs([f"virustotal={ENV}"], {ENV: KEY, "AITERPRISE_VIRUSTOTAL_MAX_LOOKUPS": bad})
            self.assertIn("AITERPRISE_VIRUSTOTAL_MAX_LOOKUPS", str(ctx.exception))


SHA = "ab" * 32
NOT_FOUND = (404, {"error": {"code": "NotFoundError", "message": "File not found"}})


def stats(malicious=0, suspicious=0, harmless=0, undetected=60):
    """A VirusTotal v3 file object, cut down to what the adapter reads."""
    return 200, {"data": {"type": "file", "attributes": {"last_analysis_stats": {
        "malicious": malicious, "suspicious": suspicious, "harmless": harmless, "undetected": undetected,
        "type-unsupported": 3, "timeout": 0, "confirmed-timeout": 0, "failure": 0}}}}


def vt_error(status, code):
    return status, {"error": {"code": code, "message": code}}


class StubVirusTotal:
    """A local stand-in for the VirusTotal API: one canned answer per SHA-256, every request recorded."""

    def __init__(self):
        self.answers = {}  # sha256 -> (status, body[, headers]) or a callable; anything else gets VT's 404
        self.requests = []  # (method, path, lower-cased headers, body bytes)

    def serving(self, answers=None):
        """Forget earlier requests and answer with `answers` from now on."""
        self.answers = dict(answers or {})
        self.requests = []
        return self

    def start(self):
        stub = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def serve(self):
                length = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(length) if length else b""
                stub.requests.append((self.command, self.path, {k.lower(): v for k, v in self.headers.items()}, body))
                answer = stub.answers.get(self.path.rsplit("/", 1)[-1], NOT_FOUND)
                status, doc, *rest = answer(self) if callable(answer) else answer
                raw = json.dumps(doc).encode("utf-8")
                try:
                    self.send_response(status)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(raw)))
                    for name, value in (rest[0] if rest else {}).items():
                        self.send_header(name, value)
                    self.end_headers()
                    self.wfile.write(raw)
                except OSError:
                    pass  # the client gave up (the timeout test)

            do_GET = do_POST = do_PUT = serve

            def log_message(self, *a):
                pass

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"

    def stop(self):
        self.server.shutdown()
        self.server.server_close()

    @property
    def looked_up(self):
        return [path.rsplit("/", 1)[-1] for _method, path, _headers, _body in self.requests]


# One listener for the whole module (a new one per test is slow on Windows), and a second host
# that must never be contacted.
STUB = StubVirusTotal()
ELSEWHERE = StubVirusTotal()


def setUpModule():
    STUB.start()
    ELSEWHERE.start()


def tearDownModule():
    STUB.stop()
    ELSEWHERE.stop()


def adapter(**kw):
    return VirusTotal(key=KEY, base_url=STUB.url, **kw)


def target(sha=SHA, name="model.pkl"):
    return FileTarget(name=name, location=f"models/{name}", sha256=sha)


class VirusTotalAdapterTests(unittest.TestCase):
    def lookup(self, answer, **kw):
        """(known to VirusTotal, the finding about the file or None) for one canned answer."""
        STUB.serving({SHA: answer})
        vt = adapter(**kw)
        got = vt.lookup(SHA)
        return got is not None, (vt.finding(target(), got) if got is not None else None)

    def test_a_lookup_is_one_get_of_the_sha256_with_the_key_in_a_header(self):
        self.lookup(stats())
        (method, path, headers, body), = STUB.requests
        self.assertEqual((method, path, body), ("GET", f"/api/v3/files/{SHA}", b""))
        self.assertEqual(headers["x-apikey"], KEY)
        self.assertNotIn(KEY, path)

    def test_five_or_more_malicious_engines_is_high(self):
        _, f = self.lookup(stats(malicious=5, undetected=65))
        self.assertEqual((f.rule_id, f.severity), ("ext.virustotal.malicious", "high"))
        self.assertIn("5 of 70 engines", f.title)

    def test_a_provider_never_sets_our_malicious_verdict(self):
        # "malicious" is our own judgement (known-malicious data, protected from blanket suppression,
        # shown as "Known-malicious"); a third party's count of engines is reported as suspicious
        from aiterprise_scan import policy

        _, f = self.lookup(stats(malicious=40, undetected=30))
        self.assertEqual((f.severity, f.verdict), ("high", "suspicious"))
        self.assertFalse(policy.is_protected(f))

    def test_one_to_four_malicious_engines_is_medium_and_says_it_can_be_a_false_positive(self):
        for n in (1, 4):
            with self.subTest(malicious=n):
                _, f = self.lookup(stats(malicious=n, undetected=70 - n))
                self.assertEqual((f.rule_id, f.severity, f.verdict), ("ext.virustotal.suspicious", "medium", "suspicious"))
                self.assertIn(f"{n} of 70 engines", f.title)
                self.assertIn("false positive", f.title)

    def test_suspicious_engines_alone_are_medium(self):
        _, f = self.lookup(stats(suspicious=9, undetected=61))
        self.assertEqual((f.rule_id, f.severity, f.verdict), ("ext.virustotal.suspicious", "medium", "suspicious"))
        self.assertIn("9 of 70 engines", f.title)
        self.assertIn("false positive", f.title)

    def test_no_engine_flagging_the_file_is_no_finding(self):
        known, f = self.lookup(stats(harmless=2, undetected=68))
        self.assertEqual((known, f), (True, None))

    def test_a_404_means_unknown_to_virustotal(self):
        known, f = self.lookup(NOT_FOUND)
        self.assertEqual((known, f), (False, None))

    def test_a_finding_is_labelled_as_virustotals_not_ours(self):
        _, f = self.lookup(stats(malicious=12, suspicious=1, harmless=3, undetected=54))
        link = f"https://www.virustotal.com/gui/file/{SHA}"
        self.assertTrue(f.rule_id.startswith("ext.virustotal."))
        self.assertTrue(f.title.startswith("VirusTotal: "), f.title)
        ev = f.evidence[0].to_dict()
        self.assertEqual((ev["source"], ev["provider"], ev["record"], ev["url"]), ("virustotal", "VirusTotal", SHA, link))
        self.assertEqual(ev["engines"], {"malicious": 12, "suspicious": 1, "harmless": 3, "undetected": 54})
        self.assertIn(link, f.remediation)
        self.assertEqual(str(f.location), "models/model.pkl")

    def test_quota_auth_and_server_errors_carry_their_status(self):
        for status, code in ((429, "QuotaExceededError"), (401, "WrongCredentialsError"), (403, "ForbiddenError"),
                             (500, "TransientError")):
            with self.subTest(status=status), self.assertRaises(ProviderError) as ctx:
                self.lookup(vt_error(status, code))
            self.assertEqual(ctx.exception.status, status)

    def test_a_timeout_is_an_error_without_a_status(self):
        def slow(handler):
            time.sleep(1.0)
            return stats()

        with self.assertRaises(ProviderError) as ctx:
            self.lookup(slow, timeout=0.2)
        self.assertEqual((ctx.exception.status, str(ctx.exception)), (None, "timed out"))

    def test_an_answer_without_engine_counts_is_an_error(self):
        for body in ({}, {"data": {"attributes": {}}}, {"data": {"attributes": {"last_analysis_stats": {"malicious": "x"}}}},
                     ["not", "an", "object"]):
            with self.subTest(body=body), self.assertRaises(ProviderError):
                self.lookup((200, body))

    def test_a_redirect_is_not_followed_so_the_key_goes_nowhere_else(self):
        ELSEWHERE.serving()
        moved = (302, {}, {"Location": f"{ELSEWHERE.url}/api/v3/files/{SHA}"})
        with self.assertRaises(ProviderError) as ctx:
            self.lookup(moved)
        self.assertEqual(ctx.exception.status, 302)
        self.assertEqual(ELSEWHERE.requests, [])

    def test_error_text_never_holds_the_key_even_when_the_server_echoes_it(self):
        echo = (403, {"error": {"code": "ForbiddenError", "message": f"key {KEY} is not allowed"}})
        with self.assertRaises(ProviderError) as ctx:
            self.lookup(echo)
        self.assertNotIn(KEY, str(ctx.exception) + repr(ctx.exception))


    def test_a_record_no_engine_has_judged_is_unknown(self):
        known, f = self.lookup(stats(undetected=0))
        self.assertEqual((known, f), (False, None))

    def test_anything_but_a_sha256_is_never_sent(self):
        STUB.serving()
        for value in ("", "../../users/me", "ab" * 31, "zz" * 32):
            with self.subTest(value=value), self.assertRaises(ProviderError):
                adapter().lookup(value)
        self.assertEqual(STUB.requests, [])


def sha_of(n):
    return f"{n:064x}"


def model_file(digest, name="model.pkl", fmt="pickle"):
    return Component(name, ctype="model-file", locations=[Location(name)], hashes={"sha256": digest} if digest else {},
                     source="file", properties={"path": name, "format": fmt})


def our_finding(comp, severity):
    return Finding("ait.model.pickle.dangerous-callable", "x", severity, component=comp)


class EnrichTests(unittest.TestCase):
    """The engine side: which files are asked about, in what order, and how gaps are reported."""

    def enrich(self, comps, answers=None, findings=(), offline=False, archives=(), provider=None, **kw):
        STUB.serving(answers)
        result = ScanResult("t", "offline" if offline else "online")
        out = providers.enrich([provider or adapter(**kw)], comps, list(findings), result, archives=archives,
                               offline=offline)
        return out, result

    def test_a_flagged_model_file_becomes_a_finding_on_that_file(self):
        comp = model_file(SHA)
        (f,), result = self.enrich([comp], {SHA: stats(malicious=9)})
        self.assertEqual((f.rule_id, f.component, str(f.location)), ("ext.virustotal.malicious", comp, "model.pkl"))
        ex = result.examined["virustotal"]
        self.assertEqual((ex.checked, ex.with_data, ex.errors, ex.skipped), (1, 1, 0, None))

    def test_a_file_nobody_flags_is_counted_and_never_called_clean(self):
        out, result = self.enrich([model_file(SHA)], {SHA: stats(harmless=1)})
        self.assertEqual(out, [])
        self.assertEqual((result.examined["virustotal"].checked, result.examined["virustotal"].with_data), (1, 1))
        self.assertEqual(result.notes, [])

    def test_a_hash_unknown_to_virustotal_is_counted_as_unknown_not_clean(self):
        out, result = self.enrich([model_file(SHA)])
        self.assertEqual(out, [])
        self.assertEqual((result.examined["virustotal"].checked, result.examined["virustotal"].with_data), (1, 0))
        self.assertEqual(len(result.notes), 1)
        self.assertIn("1 file hash(es) unknown to VirusTotal", result.notes[0])
        self.assertIn("not clean", result.notes[0])

    def test_at_most_four_lookups_by_default_and_the_rest_are_reported_not_checked(self):
        comps = [model_file(sha_of(n), f"m{n}.pkl") for n in range(6)]
        _, result = self.enrich(comps, {sha_of(n): stats() for n in range(6)})
        self.assertEqual(len(STUB.requests), 4)
        self.assertEqual(result.examined["virustotal"].checked, 4)
        note = "\n".join(result.notes)
        self.assertIn("2 file(s) not checked", note)
        self.assertIn("not verified with VirusTotal", note)
        self.assertIn("AITERPRISE_VIRUSTOTAL_MAX_LOOKUPS", note)
        self.assertEqual(result.examined["virustotal"].errors, 0)

    def test_the_budget_goes_to_the_most_suspicious_files_first(self):
        plain = model_file(sha_of(1), "a-weights.safetensors", "safetensors")
        pickled = model_file(sha_of(2), "b-pickled.pkl")
        low = model_file(sha_of(3), "c-low.safetensors", "safetensors")
        critical = model_file(sha_of(4), "d-critical.pkl")
        by_ext = model_file(sha_of(5), "e-checkpoint.pt", "pytorch")
        self.enrich([plain, pickled, low, critical, by_ext], max_lookups=5,
                    findings=[our_finding(low, "low"), our_finding(critical, "critical")])
        self.assertEqual(STUB.looked_up, [sha_of(4), sha_of(3), sha_of(2), sha_of(5), sha_of(1)])

    def test_quota_exhaustion_stops_the_calls_and_is_reported_not_verified(self):
        comps = [model_file(sha_of(n), f"m{n}.pkl") for n in range(3)]
        out, result = self.enrich(comps, {sha_of(0): vt_error(429, "QuotaExceededError")})
        self.assertEqual(out, [])
        self.assertEqual(len(STUB.requests), 1)
        ex = result.examined["virustotal"]
        self.assertEqual((ex.checked, ex.with_data, ex.errors), (0, 0, 0))  # 429 degrades, it is not a crash
        self.assertIn("quota", ex.skipped)
        self.assertEqual(len(result.notes), 1)
        self.assertIn("quota reached (HTTP 429); 3 file(s) not verified with VirusTotal, not clean", result.notes[0])

    def test_a_refused_key_stops_the_calls_and_is_reported_not_verified(self):
        for status in (401, 403):
            with self.subTest(status=status):
                comps = [model_file(sha_of(n), f"m{n}.pkl") for n in range(3)]
                out, result = self.enrich(comps, {sha_of(0): vt_error(status, "WrongCredentialsError")})
                self.assertEqual(out, [])
                self.assertEqual(len(STUB.requests), 1)
                self.assertIn(f"key refused (HTTP {status})", result.examined["virustotal"].skipped)
                self.assertIn("3 file(s) not verified with VirusTotal, not clean", "\n".join(result.notes))
                self.assertNotIn(KEY, "\n".join(result.notes))

    def test_an_outage_is_an_error_and_is_reported_not_verified(self):
        comps = [model_file(sha_of(n), f"m{n}.pkl") for n in range(2)]
        out, result = self.enrich(comps, {sha_of(0): vt_error(500, "TransientError")})
        self.assertEqual(out, [])
        self.assertEqual(len(STUB.requests), 1)
        self.assertEqual(result.examined["virustotal"].errors, 1)
        self.assertIn("lookup failed (HTTP 500); 2 file(s) not verified with VirusTotal, not clean",
                      "\n".join(result.notes))

    def test_an_earlier_answer_is_kept_when_a_later_call_fails(self):
        comps = [model_file(sha_of(0), "m0.pkl"), model_file(sha_of(1), "m1.pkl")]
        out, result = self.enrich(comps, {sha_of(0): stats(malicious=7), sha_of(1): vt_error(429, "QuotaExceededError")})
        self.assertEqual([f.rule_id for f in out], ["ext.virustotal.malicious"])
        self.assertEqual(result.examined["virustotal"].checked, 1)
        self.assertIn("1 file(s) not verified with VirusTotal", "\n".join(result.notes))

    def test_offline_makes_no_call_and_says_so(self):
        out, result = self.enrich([model_file(SHA)], {SHA: stats(malicious=9)}, offline=True)
        self.assertEqual(out, [])
        self.assertEqual(STUB.requests, [])
        self.assertIn("offline", result.examined["virustotal"].skipped)
        self.assertIn("--offline", result.notes[0])
        self.assertIn("1 file(s) not verified with VirusTotal", result.notes[0])

    def test_the_same_content_in_two_places_costs_one_lookup_and_reports_both(self):
        comps = [model_file(SHA, "a/model.pkl"), model_file(SHA, "b/copy.pkl")]
        out, result = self.enrich(comps, {SHA: stats(malicious=9)})
        self.assertEqual(len(STUB.requests), 1)
        self.assertEqual(sorted(str(f.location) for f in out), ["a/model.pkl", "b/copy.pkl"])
        self.assertEqual(len({f.fingerprint for f in out}), 2)
        self.assertIn("copy.pkl", " ".join(f.title for f in out))
        self.assertEqual(result.examined["virustotal"].checked, 2)

    def test_an_archive_is_looked_up_by_the_sha256_of_the_file_and_nothing_of_it_is_sent(self):
        with tempfile.TemporaryDirectory() as tmp:
            wheel = Path(tmp) / "demo-1.0-py3-none-any.whl"
            wheel.write_bytes(b"PK\x03\x04 not really a wheel, only bytes to hash")
            digest = hashlib.sha256(wheel.read_bytes()).hexdigest()
            (f,), _ = self.enrich([], {digest: stats(malicious=6)}, archives=[("dist/demo-1.0-py3-none-any.whl", wheel)])
        self.assertEqual(STUB.looked_up, [digest])
        self.assertEqual((str(f.location), f.evidence[0].record), ("dist/demo-1.0-py3-none-any.whl", digest))
        self.assertEqual([(m, body) for m, _path, _headers, body in STUB.requests], [("GET", b"")])

    def test_a_file_that_was_not_hashed_is_reported_not_verified(self):
        out, result = self.enrich([model_file(None)])
        self.assertEqual((out, STUB.requests), ([], []))
        self.assertIn("1 file(s) could not be hashed; not verified with VirusTotal", "\n".join(result.notes))

    def test_a_crashing_adapter_ends_as_an_error_note_without_the_key(self):
        class Broken(VirusTotal):
            def lookup(self, sha256):
                raise RuntimeError(f"header x-apikey: {self.key} rejected")

        out, result = self.enrich([model_file(SHA)], provider=Broken(key=KEY, base_url=STUB.url))
        self.assertEqual(out, [])
        self.assertEqual(result.examined["virustotal"].errors, 1)
        note = "\n".join(result.notes)
        self.assertIn("not verified with VirusTotal", note)
        self.assertNotIn(KEY, note)


BENIGN_PICKLE = pickle.dumps({"weights": [1, 2, 3]}, protocol=2)  # produced here, never loaded
BENIGN_SHA = hashlib.sha256(BENIGN_PICKLE).hexdigest()


class ScanCase(unittest.TestCase):
    """A scan through the real CLI of a directory holding one harmless pickle, the stub as VirusTotal."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        base = Path(self.tmp.name)
        self.repo, self.home, self.cache = base / "repo", base / "home", base / "cache"
        self.repo.mkdir()
        (self.repo / "model.pkl").write_bytes(BENIGN_PICKLE)
        self.env = {"AITERPRISE_HOME": str(self.home), "AITERPRISE_CACHE_DIR": str(self.cache), ENV: KEY,
                    "AITERPRISE_VIRUSTOTAL_URL": STUB.url}
        self.urls = []  # every URL the scanner asked for
        real = net.request

        def recording(method, url, *a, **kw):
            self.urls.append(url)
            return real(method, url, *a, **kw)

        patcher = mock.patch.object(net, "request", recording)
        patcher.start()
        self.addCleanup(patcher.stop)
        os.environ.pop("AITERPRISE_API_KEY", None)  # no SecDB credential: BYO works anonymously
        STUB.serving({BENIGN_SHA: stats(malicious=11, undetected=59)})

    def scan(self, *args, byo=True, env=None):
        argv = ["scan", str(self.repo), *(("--byo", f"virustotal={ENV}") if byo else ()), *args]
        return run_cli(argv, {**self.env, **(env or {})})

    def scan_json(self, *args, **kw):
        code, out, err = self.scan("--format", "json", *args, **kw)
        return code, json.loads(out), err


class ScanByoTests(ScanCase):
    def test_the_provider_finding_is_reported_under_its_own_rule_id(self):
        code, doc, _ = self.scan_json()
        (f,) = [f for f in doc["findings"] if f["rule_id"].startswith("ext.")]
        self.assertEqual((f["rule_id"], f["severity"], f["location"]), ("ext.virustotal.malicious", "high", "model.pkl"))
        self.assertEqual(f["component"]["name"], "model.pkl")
        self.assertEqual(doc["examined"]["virustotal"], {"checked": 1, "with_data": 1})
        self.assertEqual(code, 1)  # a high finding fails the default gate like any other

    def test_only_the_hash_is_asked_about_and_only_virustotal_is_contacted(self):
        self.scan_json()
        self.assertEqual(STUB.looked_up, [BENIGN_SHA])
        self.assertEqual([u for u in self.urls if not u.startswith(STUB.url + "/")], [])
        (method, _path, _headers, body), = STUB.requests
        self.assertEqual((method, body), ("GET", b""))

    def test_no_secdb_sign_in_is_needed(self):
        _, doc, _ = self.scan_json()
        self.assertIn("not logged in", doc["examined"]["secdb"]["skipped"])
        self.assertTrue(any(f["rule_id"] == "ext.virustotal.malicious" for f in doc["findings"]))

    def test_without_byo_nothing_is_asked(self):
        _, doc, _ = self.scan_json(byo=False)
        self.assertEqual(STUB.requests, [])
        self.assertNotIn("virustotal", doc["examined"])

    def test_a_package_archive_is_looked_up_by_its_own_sha256(self):
        wheel = self.repo / "demo_pkg-1.0.0-py3-none-any.whl"
        with zipfile.ZipFile(wheel, "w") as zf:
            zf.writestr("demo_pkg-1.0.0.dist-info/METADATA", "Metadata-Version: 2.1\nName: demo-pkg\nVersion: 1.0.0\n")
            zf.writestr("demo_pkg/__init__.py", "")
        digest = hashlib.sha256(wheel.read_bytes()).hexdigest()
        STUB.serving({digest: stats(malicious=6, undetected=64)})
        Cache(self.cache).put("osv-query", "PyPI|demo-pkg|1.0.0", [])  # OSV already answered: no call to it
        _, doc, _ = self.scan_json("--no-registry")
        self.assertEqual([u for u in self.urls if not u.startswith(STUB.url + "/")], [])
        self.assertIn(digest, STUB.looked_up)
        (f,) = [f for f in doc["findings"] if f["rule_id"].startswith("ext.")]
        self.assertEqual((f["location"], f["component"]["name"]), ("demo_pkg-1.0.0-py3-none-any.whl", "demo-pkg"))

    def test_offline_with_byo_makes_no_call_and_says_so(self):
        code, out, _ = self.scan("--offline")
        self.assertEqual(STUB.requests, [])
        self.assertIn("virustotal skipped (offline)", out)
        self.assertIn("virustotal: --offline, no call was made; 1 file(s) not verified with VirusTotal", out)
        self.assertEqual(code, 0)

    def test_quota_exhaustion_is_reported_as_not_verified_and_does_not_fail_the_scan(self):
        STUB.serving({BENIGN_SHA: vt_error(429, "QuotaExceededError")})
        code, out, _ = self.scan()
        self.assertEqual(code, 0)
        self.assertIn("quota reached (HTTP 429); 1 file(s) not verified with VirusTotal, not clean", out)

    def test_an_outage_makes_the_scan_incomplete(self):
        STUB.serving({BENIGN_SHA: vt_error(503, "TransientError")})
        code, out, _ = self.scan()
        self.assertEqual(code, 2)
        self.assertIn("lookup failed (HTTP 503); 1 file(s) not verified with VirusTotal, not clean", out)
        self.assertEqual(len(STUB.requests), 1)  # not retried, no sleep

    def test_the_budget_override_is_read_from_the_environment(self):
        for n in range(3):
            (self.repo / f"extra{n}.pkl").write_bytes(pickle.dumps({"n": n}, protocol=2))
        code, out, _ = self.scan(env={"AITERPRISE_VIRUSTOTAL_MAX_LOOKUPS": "2"})
        self.assertEqual(len(STUB.requests), 2)
        self.assertIn("2 file(s) not checked (budget of 2 lookup(s) per scan", out)


LINK = f"https://www.virustotal.com/gui/file/{BENIGN_SHA}"


class ReportTests(ScanCase):
    """A rule id outside `ait.` works in every report, and is unmistakably the provider's."""

    def reports(self, *extra):
        out_dir = Path(self.tmp.name) / "out"
        formats = [x for fmt in ("table", "json", "sarif", "cyclonedx", "html") for x in ("--format", fmt)]
        code, out, err = self.scan(*formats, "--out", str(out_dir), *extra)
        files = {p.name: p.read_text(encoding="utf-8") for p in out_dir.iterdir()}
        self.assertEqual(sorted(files), ["aibom.cdx.json", "report.html", "report.json", "report.sarif", "report.txt"])
        return files, out + err

    def test_every_format_shows_the_rule_id_the_provider_name_and_the_report_link(self):
        files, _ = self.reports()
        for name, text in files.items():
            with self.subTest(report=name):
                self.assertIn("ext.virustotal.malicious", text)
                self.assertIn("VirusTotal: 11 of 70 engines flag model.pkl as malicious", text)
                self.assertIn(LINK, text)

    def test_json_evidence_carries_provider_engine_counts_and_link(self):
        files, _ = self.reports()
        (f,) = [f for f in json.loads(files["report.json"])["findings"] if f["rule_id"].startswith("ext.")]
        (ev,) = f["evidence"]
        self.assertEqual((ev["source"], ev["provider"], ev["url"]), ("virustotal", "VirusTotal", LINK))
        self.assertEqual(ev["engines"], {"malicious": 11, "suspicious": 0, "harmless": 0, "undetected": 59})

    def test_the_false_positive_rate_of_a_provider_finding_is_null(self):
        _, doc, _ = self.scan_json()
        (f,) = [f for f in doc["findings"] if f["rule_id"].startswith("ext.")]
        self.assertIsNone(f["quality"]["fp_rate_measured"])
        self.assertEqual(f["examined"], {"sources": 1, "with_data": 1})

    def test_sarif_keeps_the_provider_rule_apart_from_ours(self):
        files, _ = self.reports()
        run = json.loads(files["report.sarif"])["runs"][0]
        rule_ids = [r["id"] for r in run["tool"]["driver"]["rules"]]
        self.assertIn("ext.virustotal.malicious", rule_ids)
        (res,) = [r for r in run["results"] if r["ruleId"] == "ext.virustotal.malicious"]
        self.assertEqual(run["tool"]["driver"]["rules"][res["ruleIndex"]]["id"], "ext.virustotal.malicious")
        self.assertEqual(res["properties"]["evidence"][0]["provider"], "VirusTotal")

    def test_cyclonedx_lists_it_as_virustotals_and_keeps_it_out_of_the_model_card(self):
        files, _ = self.reports()
        bom = json.loads(files["aibom.cdx.json"])
        (v,) = [v for v in bom["vulnerabilities"] if v["id"] == "ext.virustotal.malicious"]
        self.assertEqual(v["source"], {"name": "virustotal", "url": LINK})
        (model,) = [c for c in bom["components"] if c["name"] == "model.pkl"]
        self.assertNotIn("VirusTotal", json.dumps(model))  # never blended into our row for the file

    def test_the_key_is_in_no_output_no_report_and_no_file_left_on_disk(self):
        files, printed = self.reports("--save")
        self.assertIn("saved to history", printed)
        self.assertNotIn(KEY, printed)
        for name, text in files.items():
            with self.subTest(report=name):
                self.assertNotIn(KEY, text)
        left = [p for p in Path(self.tmp.name).rglob("*") if p.is_file()]
        self.assertTrue(any("history" in p.parts for p in left))
        for path in left:
            with self.subTest(file=path.name):
                self.assertNotIn(KEY.encode(), path.read_bytes())

    def test_a_server_that_echoes_the_key_does_not_get_it_into_the_report(self):
        STUB.serving({BENIGN_SHA: (403, {"error": {"code": "ForbiddenError", "message": f"bad key {KEY}"}})})
        files, printed = self.reports()
        self.assertIn("key refused (HTTP 403)", files["report.txt"])
        self.assertNotIn(KEY, printed + "".join(files.values()))


SECDB_KEY = "aik_live_" + "F" * 36  # fake


class FakeAiterprise:
    """Stands in for SecDB or an AIterprise cloud at the transport: records what would be sent."""

    def __init__(self):
        self.calls = []  # (method, url, body, headers)

    def __call__(self, method, url, body, headers):
        self.calls.append((method, url, body, dict(headers)))
        return net.Response(201, {}, {"scan_id": "scan_1", "status": "stored", "findings_new": 0,
                                      "report_id": "rpt_1"})

    @property
    def sent(self):
        return json.dumps([(url, body, headers) for _method, url, body, headers in self.calls])


class NothingLeavesForAiterpriseTests(ScanCase):
    """FD22: provider results are never sent to SecDB or a cloud, cached, or written to definitions."""

    def setUp(self):
        super().setUp()
        self.fake = FakeAiterprise()
        patcher = mock.patch.object(secdb, "DEFAULT_TRANSPORT", self.fake)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.env["AITERPRISE_API_KEY"] = SECDB_KEY

    def assert_no_provider_data(self, sent):
        for word in ("virustotal", "engines"):  # the rule ids, titles, links and evidence all carry these
            self.assertNotIn(word, sent.lower())
        self.assertNotIn(KEY, sent)

    def test_scan_upload_leaves_provider_findings_out_and_says_so(self):
        for where in ((), ("--cloud", "https://cloud.test")):
            with self.subTest(where=where):
                self.fake.calls.clear()
                code, doc, err = self.scan_json("--upload", "--no-secdb", *where)
                (_method, _url, body, headers), = self.fake.calls
                uploaded = body["document"]
                self.assert_no_provider_data(self.fake.sent)
                self.assertEqual([f["rule_id"] for f in uploaded["findings"]], ["ait.model.pickle.format"])
                self.assertEqual(uploaded["summary"]["findings"], 1)
                self.assertEqual(uploaded["summary"]["severity"]["high"], 0)
                self.assertNotIn("x-apikey", {k.lower() for k in headers})
                self.assertIn("1 VirusTotal finding(s) kept local, not uploaded", err)
                # the report on this machine still has it
                self.assertIn("ext.virustotal.malicious", [f["rule_id"] for f in doc["findings"]])

    def test_upload_of_a_saved_report_leaves_provider_findings_out_and_says_so(self):
        _, doc, _ = self.scan_json("--no-secdb")
        report = Path(self.tmp.name) / "report.json"
        report.write_text(json.dumps(doc), encoding="utf-8")
        code, _, err = run_cli(["upload", str(report)], self.env)
        self.assertEqual(code, 0, err)
        self.assert_no_provider_data(self.fake.sent)
        self.assertEqual(len(self.fake.calls[0][2]["document"]["findings"]), 1)
        self.assertIn("1 VirusTotal finding(s) kept local, not uploaded", err)

    def test_coverage_and_notes_about_the_provider_are_left_out_too(self):
        STUB.serving()  # the hash is unknown to VirusTotal: a note and an `examined` entry, no finding
        self.scan_json("--upload", "--no-secdb")
        uploaded = self.fake.calls[0][2]["document"]
        self.assertNotIn("virustotal", uploaded["examined"])
        self.assertNotIn("virustotal", json.dumps(uploaded).lower())
        self.assertIn("model-files", uploaded["examined"])

    def test_an_upload_without_provider_findings_prints_no_note(self):
        _, _, err = self.scan_json("--upload", "--no-secdb", byo=False)
        self.assertEqual(len(self.fake.calls), 1)
        self.assertNotIn("kept local", err)

    def test_report_fp_refuses_a_provider_rule(self):
        code, out, err = run_cli(["report-fp", "ext.virustotal.malicious", "--yes", "--notes", "x"], self.env)
        self.assertEqual(code, 2)
        self.assertEqual(self.fake.calls, [])
        self.assertIn("VirusTotal", err)
        self.assertIn("never sent", err)

    def test_the_client_itself_refuses_to_send_provider_results(self):
        client = secdb.Client(credentials.Credential("api_key", SECDB_KEY, "env"), base_url="https://secdb.test")
        with self.assertRaises(ValueError):
            client.report("false_positive", rule_id="ext.virustotal.suspicious")
        self.assertEqual(self.fake.calls, [])
        doc = {"target": "demo", "findings": [{"rule_id": "ext.virustotal.malicious", "severity": "high",
                                               "status": "new", "title": "VirusTotal: flagged"}]}
        client.upload_scan("demo", doc, "2026-11-14T00:00:00Z")
        self.assertEqual(self.fake.calls[0][2]["document"]["findings"], [])
        self.assertEqual(len(doc["findings"]), 1)  # the caller's document is untouched

    def test_provider_answers_are_never_cached_or_stored(self):
        self.scan_json("--no-secdb")
        self.scan_json("--no-secdb")
        self.assertEqual(STUB.looked_up, [BENIGN_SHA, BENIGN_SHA])  # asked again: nothing was remembered
        for path in (p for p in Path(self.tmp.name).rglob("*") if p.is_file() and self.repo not in p.parents):
            blob = path.read_bytes().lower()
            with self.subTest(file=path.name):
                self.assertNotIn(b"virustotal", blob)
                self.assertNotIn(BENIGN_SHA.encode(), blob)

    def test_the_providers_package_cannot_reach_the_cache_the_definitions_or_secdb(self):
        forbidden = {"cache", "data", "bundles", "defscli", "secdb", "account", "history", "credentials"}
        package = Path(providers.__file__).parent
        for source in sorted(package.glob("*.py")):
            imported = set()
            for node in ast.walk(ast.parse(source.read_text(encoding="utf-8"))):
                if isinstance(node, ast.ImportFrom):
                    imported |= {(node.module or "").split(".")[0]} | {a.name for a in node.names}
                elif isinstance(node, ast.Import):
                    imported |= {a.name.split(".")[-1] for a in node.names}
            with self.subTest(module=source.name):
                self.assertEqual(imported & forbidden, set())

    def test_the_adapter_only_ever_issues_get_requests(self):
        package = Path(providers.__file__).parent
        text = "".join(p.read_text(encoding="utf-8") for p in package.glob("*.py"))
        self.assertEqual(sorted(set(re.findall(r'net\.request\(\s*"(\w+)"', text))), ["GET"])
        self.assertNotIn("urlopen", text)


class DocsTests(unittest.TestCase):
    def test_the_docs_page_names_the_real_variables_rule_ids_and_terms(self):
        root = Path(__file__).resolve().parents[1]
        text = (root / "docs" / "providers.md").read_text(encoding="utf-8")
        for word in (VirusTotal.url_env(), VirusTotal.budget_env(), "ext.virustotal.malicious",
                     "ext.virustotal.suspicious", "--byo virustotal=", "non-commercial",
                     f"(default {VirusTotal.default_max_lookups})"):
            with self.subTest(word=word):
                self.assertIn(word, text)
        self.assertIn("--byo virustotal=", (root / "README.md").read_text(encoding="utf-8"))


class QualityGuardTests(unittest.TestCase):
    """FD22: nothing is measured or tuned from provider results."""

    def test_provider_rules_are_never_given_a_measured_rate(self):
        from aiterprise_scan import quality

        planted = {"ext.virustotal.malicious": {"fp_rate_measured": 0.01, "samples": 100},
                   "ext.*": {"fp_rate_measured": 0.02, "samples": 100}}
        with mock.patch.object(quality, "_measured", return_value=planted):
            for rule in ("ext.virustotal.malicious", "ext.virustotal.suspicious", "ext.other.thing"):
                with self.subTest(rule=rule):
                    self.assertEqual(quality.rule_quality(rule),
                                     {"fp_rate_measured": None, "corpus": None, "evaluated_at": None})

    def test_our_own_rules_keep_their_measured_rate(self):
        from aiterprise_scan import quality

        self.assertIsNotNone(quality.rule_quality("ait.secret.private-key")["fp_rate_measured"])


class ByoCliUsageTests(unittest.TestCase):
    """A bad --byo is a usage error (exit 2) before anything is scanned, and the key is never printed."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.env = {"AITERPRISE_HOME": str(Path(self.tmp.name) / "home"),
                    "AITERPRISE_CACHE_DIR": str(Path(self.tmp.name) / "cache")}

    def scan(self, *byo, env=None):
        with mock.patch("aiterprise_scan.cli.run_scan") as run_scan:
            code, out, err = run_cli(["scan", self.tmp.name, "--offline", *byo], {**self.env, **(env or {})})
        return code, out + err, run_scan

    def test_an_unknown_provider_exits_2_before_the_scan(self):
        code, text, run_scan = self.scan("--byo", f"nosuchprovider={ENV}", env={ENV: KEY})
        self.assertEqual(code, 2)
        self.assertIn("unknown provider", text)
        run_scan.assert_not_called()

    def test_an_unset_variable_exits_2_before_the_scan(self):
        os.environ.pop(ENV, None)
        code, text, run_scan = self.scan("--byo", f"virustotal={ENV}")
        self.assertEqual(code, 2)
        self.assertIn("not set", text)
        run_scan.assert_not_called()

    def test_a_key_on_the_command_line_exits_2_and_is_not_printed(self):
        code, text, run_scan = self.scan("--byo", f"virustotal={KEY}")
        self.assertEqual(code, 2)
        self.assertIn("never the key itself", text)
        self.assertNotIn(KEY, text)
        run_scan.assert_not_called()

    def test_a_key_typed_after_a_space_instead_of_an_equals_sign_is_not_printed(self):
        # `--byo virustotal KEY`: the key lands where the scan target goes
        with mock.patch("aiterprise_scan.cli.run_scan") as run_scan:
            code, out, err = run_cli(["scan", "--offline", "--byo", "virustotal", KEY], self.env)
        self.assertEqual(code, 2)
        self.assertIn("--byo expects PROVIDER=ENV_VAR", err)
        self.assertNotIn(KEY, out + err)
        run_scan.assert_not_called()

    def test_a_bad_base_url_exits_2_before_the_scan(self):
        code, text, run_scan = self.scan("--byo", f"virustotal={ENV}",
                                         env={ENV: KEY, "AITERPRISE_VIRUSTOTAL_URL": "http://vt-proxy.example.com"})
        self.assertEqual(code, 2)
        self.assertIn("plain http", text)
        self.assertNotIn(KEY, text)
        run_scan.assert_not_called()


if __name__ == "__main__":
    unittest.main()
