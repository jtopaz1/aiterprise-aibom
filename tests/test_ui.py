"""Local web UI (`aiterprise-scan ui`): access control, escaping, history, diff, suppress-with-expiry."""

import datetime as dt
import http.client
import json
import os
import re
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock
from urllib.parse import urlencode

from aiterprise_scan import history, policy, ui


def report(target, findings, components=None, started="2026-11-14T10:00:00Z"):
    return {"tool": "aiterprise-scan", "version": "t", "target": target, "mode": "repo", "started_at": started,
            "duration_s": 1.0, "summary": {"components": len(components or []), "ai_components": 0, "findings":
                                           len(findings), "severity": {"critical": 0, "high": len(findings),
                                                                       "medium": 0, "low": 0, "info": 0}},
            "examined": {"osv": {"checked": 3, "with_data": 1}}, "notes": [], "notices": [],
            "components": components or [], "findings": findings, "exit_code": 1}


def finding(fp, title="t", rule="ait.test.rule", verdict="suspicious"):
    return {"fingerprint": fp, "rule_id": rule, "title": title, "severity": "high", "verdict": verdict,
            "confidence": 80, "evidence": [], "status": "new", "location": "requirements.txt:1"}


class QualityTextTests(unittest.TestCase):
    def test_measured_and_unmeasured(self):
        self.assertEqual(ui.quality_text({"fp_rate_measured": None}), "false-positive rate not yet measured")
        self.assertEqual(ui.quality_text(None), "false-positive rate not yet measured")
        self.assertEqual(ui.quality_text({"fp_rate_measured": 0.012, "corpus": "c (80 projects)", "scope": "family"}),
                         "false-positive rate 1.2% (rule family) on c (80 projects)")


class HistoryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.env = mock.patch.dict(os.environ, {"AITERPRISE_HOME": self.tmp.name})
        self.env.start()

    def tearDown(self):
        self.env.stop()
        self.tmp.cleanup()

    def test_save_list_load_delete(self):
        a = history.save(report("/w/a", [finding("1" * 16)], started="2026-11-14T10:00:00Z"))
        b = history.save(report("/w/b", [], started="2026-11-14T11:00:00Z"))
        listed = history.list_scans()
        self.assertEqual([s["id"] for s in listed], [b, a])  # newest first
        self.assertEqual(listed[1]["project"], "a")
        self.assertEqual(history.load(a)["target"], "/w/a")
        history.delete(a)
        self.assertEqual([s["id"] for s in history.list_scans()], [b])
        with self.assertRaises(KeyError):
            history.load("../../etc/passwd")

    def test_diff_by_fingerprint(self):
        old = report("/w/a", [finding("1" * 16), finding("2" * 16)], [{"name": "x", "type": "library"}])
        new = report("/w/a", [finding("2" * 16), finding("3" * 16)], [{"name": "y", "type": "library"}])
        d = history.diff(old, new)
        self.assertEqual([f["fingerprint"] for f in d["new"]], ["3" * 16])
        self.assertEqual([f["fingerprint"] for f in d["fixed"]], ["1" * 16])
        self.assertEqual([f["fingerprint"] for f in d["unchanged"]], ["2" * 16])
        self.assertEqual(d["components_added"], ["library y"])
        self.assertEqual(d["components_removed"], ["library x"])


class LocalSuppressionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_add_validates_and_the_policy_loader_merges_it(self):
        today = dt.date(2026, 11, 14)
        with self.assertRaisesRegex(ValueError, "reason"):
            policy.add_local_suppression(self.root, "a" * 16, "2026-12-01", "", today=today)
        with self.assertRaisesRegex(ValueError, "future"):
            policy.add_local_suppression(self.root, "a" * 16, "2026-11-01", "r", today=today)
        with self.assertRaisesRegex(ValueError, "365"):
            policy.add_local_suppression(self.root, "a" * 16, "2028-01-01", "r", today=today)
        with self.assertRaisesRegex(ValueError, "fingerprint"):
            policy.add_local_suppression(self.root, "not-hex", "2026-12-01", "r", today=today)
        policy.add_local_suppression(self.root, "a" * 16, "2026-12-01", "vendor fix due", approved_by="me",
                                     today=today)
        saved = json.loads((self.root / ".aiterprise" / "suppressions.json").read_text(encoding="utf-8"))
        self.assertEqual(saved["suppressions"][0]["finding"], "a" * 16)
        pol = policy.Policy()
        policy.merge_local_suppressions(pol, self.root)
        self.assertEqual(len(pol.suppressions), 1)
        self.assertEqual(pol.suppressions[0].until, dt.date(2026, 12, 1))
        self.assertEqual(pol.suppressions[0].origin, "local")


class ServerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.env = mock.patch.dict(os.environ, {"AITERPRISE_HOME": str(Path(self.tmp.name) / "home")})
        self.env.start()
        os.environ.pop("AITERPRISE_API_KEY", None)
        self.server = ui.make_server(port=0, token="T" * 32)
        self.port = self.server.server_address[1]
        self.server.serve_in_thread()
        self.cookie = None

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.env.stop()
        self.tmp.cleanup()

    def req(self, method, path, body=None, host=None, cookie=True, origin=None, headers=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=30)
        hdrs = {"Host": host or f"127.0.0.1:{self.port}"}
        if cookie and self.cookie:
            hdrs["Cookie"] = self.cookie
        if origin:
            hdrs["Origin"] = origin
        if body is not None:
            body = urlencode(body)
            hdrs["Content-Type"] = "application/x-www-form-urlencoded"
        hdrs.update(headers or {})
        conn.request(method, path, body, hdrs)
        resp = conn.getresponse()
        data = resp.read().decode("utf-8", "replace")
        conn.close()
        return resp, data

    def login(self):
        resp, _ = self.req("GET", "/?token=" + "T" * 32)
        self.assertEqual(resp.status, 303)
        cookie = resp.getheader("Set-Cookie")
        self.assertIn("HttpOnly", cookie)
        self.assertIn("SameSite=Strict", cookie)
        self.cookie = cookie.split(";", 1)[0]

    def csrf(self, page="/"):
        _, html = self.req("GET", page)
        return re.search(r'name="csrf" value="([0-9a-f]+)"', html).group(1)

    def test_requires_the_token(self):
        resp, _ = self.req("GET", "/")
        self.assertEqual(resp.status, 401)
        resp, _ = self.req("GET", "/?token=wrong")
        self.assertEqual(resp.status, 401)
        self.login()
        resp, html = self.req("GET", "/")
        self.assertEqual(resp.status, 200)
        self.assertIn("Content-Security-Policy", dict(resp.getheaders()))
        self.assertIn("frame-ancestors 'none'", resp.getheader("Content-Security-Policy"))

    def test_referrer_policy_lets_browsers_send_a_real_origin(self):
        # with `no-referrer`, browsers send `Origin: null` on same-origin form posts, which the
        # Origin check then refuses (seen in a real browser on the Account page)
        self.login()
        resp, _ = self.req("GET", "/")
        self.assertEqual(resp.getheader("Referrer-Policy"), "same-origin")

    def test_rejects_a_foreign_host_header(self):
        self.login()
        resp, _ = self.req("GET", "/", host="evil.example")
        self.assertEqual(resp.status, 403)

    def test_posts_need_csrf_and_same_origin(self):
        self.login()
        resp, _ = self.req("POST", "/logout", {})
        self.assertEqual(resp.status, 403)
        token = self.csrf()
        resp, _ = self.req("POST", "/logout", {"csrf": token}, origin="http://evil.example")
        self.assertEqual(resp.status, 403)
        resp, _ = self.req("POST", "/logout", {"csrf": token}, origin=f"http://127.0.0.1:{self.port}")
        self.assertEqual(resp.status, 303)

    def test_scan_page_escapes_scanned_content(self):
        sid = history.save(report("/w/x", [finding("ab" * 8, title='<script>alert(1)</script>')],
                                  [{"name": '<img src=x onerror=alert(1)>', "type": "library", "ai": True}]))
        self.login()
        resp, html = self.req("GET", f"/scan/{sid}")
        self.assertEqual(resp.status, 200)
        self.assertNotIn("<script>alert(1)", html)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", html)
        _, inv = self.req("GET", f"/scan/{sid}?tab=inventory")
        self.assertNotIn("<img src=x", inv)
        resp, _ = self.req("GET", "/scan/..%2F..%2Fsecret")
        self.assertEqual(resp.status, 404)

    def test_filters_and_diff(self):
        a = history.save(report("/w/x", [finding("1" * 16, title="old one"), finding("2" * 16, title="stays")],
                                started="2026-11-14T10:00:00Z"))
        b = history.save(report("/w/x", [finding("2" * 16, title="stays"),
                                         finding("3" * 16, title="brand new", verdict="malicious")],
                                started="2026-11-14T11:00:00Z"))
        self.login()
        _, html = self.req("GET", f"/scan/{b}?verdict=malicious")
        self.assertIn("brand new", html)
        self.assertNotIn("stays", html)
        _, html = self.req("GET", f"/diff?a={a}&b={b}")
        self.assertIn("brand new", html)
        self.assertIn("old one", html)
        self.assertIn('<b class="high">1</b> new', html)

    def test_suppress_writes_an_expiring_entry_into_the_project(self):
        project = Path(self.tmp.name) / "proj"
        project.mkdir()
        sid = history.save(report(str(project), [finding("ab" * 8)]))
        self.login()
        token = self.csrf(f"/scan/{sid}")
        resp, html = self.req("POST", "/suppress", {"csrf": token, "scan": sid, "fingerprint": "ab" * 8,
                                                    "until": "2000-01-01", "reason": "x"})
        self.assertEqual(resp.status, 400)
        self.assertIn("future", html)
        until = (dt.date.today() + dt.timedelta(days=30)).isoformat()
        resp, _ = self.req("POST", "/suppress", {"csrf": token, "scan": sid, "fingerprint": "ab" * 8,
                                                 "until": until, "reason": "accepted until vendor fix"})
        self.assertEqual(resp.status, 303)
        saved = json.loads((project / ".aiterprise" / "suppressions.json").read_text(encoding="utf-8"))
        self.assertEqual(saved["suppressions"][0]["until"], until)

    def test_run_a_scan_from_the_ui(self):
        project = Path(self.tmp.name) / "repo"
        project.mkdir()
        (project / "requirements.txt").write_text("openai==1.40.0\n", encoding="utf-8")
        self.login()
        token = self.csrf()
        resp, _ = self.req("POST", "/scan", {"csrf": token, "path": str(project), "offline": "1"})
        self.assertEqual(resp.status, 303)
        job = resp.getheader("Location")
        for _ in range(200):
            _, body = self.req("GET", job.replace("/jobs/", "/api/jobs/"))
            state = json.loads(body)
            if state["status"] != "running":
                break
            time.sleep(0.05)
        self.assertEqual(state["status"], "done", state)
        scans = history.list_scans()
        self.assertEqual(len(scans), 1)
        self.assertEqual(scans[0]["project"], "repo")
        _, html = self.req("GET", f"/scan/{scans[0]['id']}?tab=inventory")
        self.assertIn("openai", html)

    def test_a_scan_from_the_ui_goes_through_the_gate(self):
        project = Path(self.tmp.name) / "gated"
        project.mkdir()
        (project / ".mcp.json").write_text(
            json.dumps({"mcpServers": {"admin": {"command": "sudo", "args": ["python", "server.py"]}}}),
            encoding="utf-8")
        first = history.load(ui.run_scan_to_history(project, offline=True, registry=False))
        self.assertEqual(first["exit_code"], 1)
        until = (dt.date.today() + dt.timedelta(days=30)).isoformat()
        policy.add_local_suppression(project, first["findings"][0]["fingerprint"], until, "accepted for this test")
        second = history.load(ui.run_scan_to_history(project, offline=True, registry=False))
        self.assertEqual(second["exit_code"], 0)

    def test_account_page_when_logged_out(self):
        self.login()
        resp, html = self.req("GET", "/account")
        self.assertEqual(resp.status, 200)
        self.assertIn("Not logged in", html)


if __name__ == "__main__":
    unittest.main()
