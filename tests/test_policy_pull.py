"""`aiterprise-scan policy pull`: the org policy from an AIterprise cloud, and the cloud-URL guard."""

import contextlib
import http.server
import io
import json
import os
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

from aiterprise_scan import cli, cloudpolicy, net, policy, secdb

KEY = "aik_live_" + "P" * 36
ORG_POLICY = b"version: 1\nuse_context: internal\nfail_on: [critical]\n"


def problem(status, ptype, detail="x"):
    return net.NetError(f"HTTP {status}", status, {"type": f"https://api.aiterprise.net/problems/{ptype}",
                                                    "title": ptype, "detail": detail, "status": status})


class FakeCloud:
    def __init__(self, respond):
        self.respond = respond
        self.calls = []

    def __call__(self, url, headers):
        self.calls.append((url, dict(headers)))
        out = self.respond(url, headers)
        if isinstance(out, Exception):
            raise out
        return out


def serve(version=3, body=ORG_POLICY):
    etag = f'"policy-v{version}"'

    def respond(url, headers):
        hdrs = {"etag": etag, "x-aibom-policy-version": str(version)}
        if headers.get("If-None-Match") == etag:
            return net.Response(304, hdrs, None)
        return net.Response(200, hdrs, body)

    return FakeCloud(respond)


class PolicyPullTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.out = self.dir / "aibom.policy.yaml"
        self.env = mock.patch.dict(os.environ, {"AITERPRISE_HOME": str(self.dir / "home"), "AITERPRISE_API_KEY": KEY})
        self.env.start()
        os.environ.pop("AITERPRISE_CLOUD_URL", None)

    def tearDown(self):
        self.env.stop()
        self.tmp.cleanup()

    def pull(self, fake, *extra):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err), \
                mock.patch.object(cloudpolicy, "TRANSPORT", fake):
            code = cli.main(["policy", "pull", "--out", str(self.out), *extra])
        return code, out.getvalue(), err.getvalue()

    def test_pull_writes_the_org_policy_and_names_its_version(self):
        fake = serve(version=3)
        code, out, err = self.pull(fake, "--cloud", "https://cloud.test/")
        self.assertEqual(code, 0, err)
        url, headers = fake.calls[0]
        self.assertEqual(url, "https://cloud.test/api/policy/pull")
        self.assertEqual(headers["Authorization"], f"Bearer {KEY}")
        self.assertIn("v3", out)
        self.assertNotIn(KEY, out + err)
        pol = policy.load_policy(self.out)
        self.assertEqual(pol.errors, [])
        self.assertEqual(pol.use_context, "internal")
        self.assertIn("version 3", self.out.read_text(encoding="utf-8").splitlines()[0])

    def test_an_unchanged_policy_is_not_rewritten(self):
        self.assertEqual(self.pull(serve(version=3), "--cloud", "https://cloud.test")[0], 0)
        before = self.out.read_bytes()
        fake = serve(version=3)
        code, out, _ = self.pull(fake, "--cloud", "https://cloud.test")
        self.assertEqual(code, 0)
        self.assertEqual(fake.calls[0][1].get("If-None-Match"), '"policy-v3"')
        self.assertIn("up to date", out)
        self.assertEqual(self.out.read_bytes(), before)

    def test_an_invalid_policy_keeps_the_local_file(self):
        self.out.write_text("version: 1\n", encoding="utf-8")
        code, _, err = self.pull(serve(body=b"version: 1\nfail_on: [urgent]\n"), "--cloud", "https://cloud.test")
        self.assertEqual(code, 2)
        self.assertIn("fail_on", err)
        self.assertEqual(self.out.read_text(encoding="utf-8"), "version: 1\n")

    def test_the_cloud_url_comes_from_the_flag_or_the_environment(self):
        fake = serve()
        code, _, err = self.pull(fake)
        self.assertEqual(code, 2)
        self.assertIn("AITERPRISE_CLOUD_URL", err)
        self.assertEqual(fake.calls, [])
        with mock.patch.dict(os.environ, {"AITERPRISE_CLOUD_URL": "https://env.cloud.test"}):
            self.assertEqual(self.pull(fake)[0], 0)
        self.assertTrue(fake.calls[0][0].startswith("https://env.cloud.test/"))

    def test_plain_http_is_refused_except_to_this_machine(self):
        fake = serve()
        code, _, err = self.pull(fake, "--cloud", "http://cloud.example.com")
        self.assertEqual(code, 2)
        self.assertIn("https", err)
        self.assertEqual(fake.calls, [])
        self.assertEqual(self.pull(fake, "--cloud", "http://127.0.0.1:8000")[0], 0)
        self.assertEqual(self.pull(fake, "--cloud", "http://localhost:8000")[0], 0)

    def test_plan_and_missing_policy_are_explained(self):
        code, _, err = self.pull(FakeCloud(lambda u, h: problem(403, "plan_required", "Org policy sync needs the team plan")),
                                 "--cloud", "https://cloud.test")
        self.assertEqual(code, 2)
        self.assertIn("team plan", err)
        code, _, err = self.pull(FakeCloud(lambda u, h: problem(404, "not_found")), "--cloud", "https://cloud.test")
        self.assertEqual(code, 2)
        self.assertIn("no org policy", err.lower())
        self.assertFalse(self.out.exists())

    def test_needs_a_login(self):
        os.environ.pop("AITERPRISE_API_KEY")
        fake = serve()
        code, _, err = self.pull(fake, "--cloud", "https://cloud.test")
        self.assertEqual(code, 2)
        self.assertIn("login", err)
        self.assertEqual(fake.calls, [])


class UploadCloudGuardTests(unittest.TestCase):
    def test_upload_refuses_plain_http_to_a_remote_cloud(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = Path(tmp) / "report.json"
            report.write_text(json.dumps({"target": "demo", "findings": []}), encoding="utf-8")
            calls = []
            with mock.patch.dict(os.environ, {"AITERPRISE_HOME": tmp, "AITERPRISE_API_KEY": KEY}), \
                    mock.patch.object(secdb, "DEFAULT_TRANSPORT", lambda *a: calls.append(a)), \
                    contextlib.redirect_stderr(io.StringIO()) as err:
                code = cli.main(["upload", str(report), "--cloud", "http://cloud.example.com"])
        self.assertEqual(code, 2)
        self.assertIn("https", err.getvalue())
        self.assertEqual(calls, [])

    def test_a_cloud_refusal_names_the_cloud_not_secdb(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = Path(tmp) / "report.json"
            report.write_text(json.dumps({"target": "demo", "findings": []}), encoding="utf-8")

            def refuse(*a):
                raise problem(403, "plan_required", "Scan upload needs the pro plan or higher (this key is on free).")

            with mock.patch.dict(os.environ, {"AITERPRISE_HOME": tmp, "AITERPRISE_API_KEY": KEY}), \
                    mock.patch.object(secdb, "DEFAULT_TRANSPORT", refuse), \
                    contextlib.redirect_stderr(io.StringIO()) as err:
                code = cli.main(["upload", str(report), "--cloud", "https://cloud.test"])
        self.assertEqual(code, 2)
        text = err.getvalue()
        self.assertIn("cloud.test", text)
        self.assertIn("needs the pro plan", text)
        self.assertNotIn("SecDB", text)
        self.assertNotIn("use --cloud", text)

    def scan_upload(self, *extra):
        with tempfile.TemporaryDirectory() as tmp:
            calls = []
            with mock.patch.dict(os.environ, {"AITERPRISE_HOME": tmp, "AITERPRISE_API_KEY": KEY}), \
                    mock.patch.object(secdb, "DEFAULT_TRANSPORT", lambda *a: calls.append(a)), \
                    mock.patch("aiterprise_scan.cli.run_scan") as run_scan, \
                    contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()) as err:
                code = cli.main(["scan", tmp, "--upload", "--no-secdb", *extra])
        return code, err.getvalue(), calls, run_scan

    def test_offline_scan_never_uploads(self):
        code, err, calls, run_scan = self.scan_upload("--offline", "--cloud", "https://cloud.test")
        self.assertEqual(code, 2)
        self.assertIn("--offline", err)
        self.assertEqual(calls, [])
        run_scan.assert_not_called()

    def test_a_bad_cloud_url_fails_before_the_scan(self):
        code, err, calls, run_scan = self.scan_upload("--cloud", "http://cloud.example.com")
        self.assertEqual(code, 2)
        self.assertIn("https", err)
        run_scan.assert_not_called()


class RawResponseTests(unittest.TestCase):
    def test_request_can_return_raw_bytes(self):
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.send_header("Content-Type", "application/yaml")
                self.send_header("ETag", '"policy-v1"')
                self.end_headers()
                self.wfile.write(ORG_POLICY)

            def log_message(self, *a):
                pass

        srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            resp = net.request("GET", f"http://127.0.0.1:{srv.server_address[1]}/x", raw=True)
        finally:
            srv.shutdown()
            srv.server_close()
        self.assertEqual(resp.data, ORG_POLICY)
        self.assertEqual(resp.headers["etag"], '"policy-v1"')


if __name__ == "__main__":
    unittest.main()
