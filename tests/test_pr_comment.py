"""The GitHub Action's pull-request comment (`action/pr_comment.py`, design doc 13 C42).

One comment per pull request, updated on every run: the script finds its own earlier comment by
the report's marker and its author, and never edits anyone else's. A token that may not comment
(a pull request from a fork gets a read-only one) is a warning, never a failed job: the gate is the
scan's exit code, not the comment.
"""

from __future__ import annotations

import importlib.util
import io
import threading
import unittest
from contextlib import redirect_stdout
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location("pr_comment", ROOT / "action" / "pr_comment.py")
pr_comment = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(pr_comment)

TOKEN = "ghs_" + "x" * 36
REPORT = "<!-- aiterprise-scan report -->\n### aiterprise-scan: fails the gate\n"
ENV = {"GITHUB_TOKEN": TOKEN, "GITHUB_REPOSITORY": "acme/app", "PR_NUMBER": "7",
       "GITHUB_API_URL": "https://api.github.com"}
BOT = {"login": "github-actions[bot]", "type": "Bot"}


class FakeGitHub:
    """GitHub's REST API for one pull request, acme/app#7. An unexpected request raises."""

    def __init__(self, comments=None, me=None, refuse=None):
        self.comments = comments or []  # every comment on the pull request, oldest first
        self.me = me  # what GET /user answers; None = 403, as for the Actions token
        self.refuse = refuse or set()  # methods answered with 403
        self.calls: list[tuple[str, str, object]] = []

    def __call__(self, method, url, payload=None):
        self.calls.append((method, url, payload))
        if method in self.refuse:
            return 403, {"message": "Resource not accessible by integration"}
        parts = urlsplit(url)
        if (parts.scheme, parts.netloc) != ("https", "api.github.com"):
            raise AssertionError(f"request to {url}")
        path = parts.path
        if path == "/user":
            return (200, self.me) if self.me else (403, {"message": "Resource not accessible by integration"})
        if method == "GET" and path == "/repos/acme/app/issues/7/comments":
            query = parse_qs(parts.query)
            if query.get("per_page") != ["100"]:
                raise AssertionError(f"page size {query.get('per_page')}")
            page = int(query["page"][0])
            return 200, self.comments[(page - 1) * 100:page * 100]
        if method == "POST":
            return 201, {"id": 999, "html_url": "https://github.com/acme/app/pull/7#issuecomment-999"}
        if method == "PATCH":
            return 200, {"id": int(path.rsplit("/", 1)[1]), "html_url": "https://github.com/acme/app/pull/7#c"}
        return 404, {"message": "Not Found"}


def run(fake, body=REPORT, env=None):
    out = io.StringIO()
    with redirect_stdout(out):
        code = pr_comment.publish(body, {**ENV, **(env or {})}, fake)
    return code, out.getvalue()


def writes(fake):
    return [(m, u) for m, u, _ in fake.calls if m in ("POST", "PATCH")]


class PrCommentTest(unittest.TestCase):
    def test_the_first_run_posts_one_comment(self):
        fake = FakeGitHub(comments=[{"id": 1, "user": {"login": "alice", "type": "User"}, "body": "LGTM"}])
        code, out = run(fake)
        self.assertEqual(code, 0)
        self.assertEqual(writes(fake), [("POST", "https://api.github.com/repos/acme/app/issues/7/comments")])
        self.assertEqual(fake.calls[-1][2], {"body": REPORT})
        self.assertIn("posted", out)

    def test_a_later_run_updates_its_own_comment(self):
        fake = FakeGitHub(comments=[{"id": 1, "user": BOT, "body": "<!-- aiterprise-scan report -->\nold"}])
        run(fake)
        self.assertEqual(writes(fake), [("PATCH", "https://api.github.com/repos/acme/app/issues/comments/1")])

    def test_it_finds_its_comment_on_a_later_page(self):
        others = [{"id": i, "user": {"login": "alice", "type": "User"}, "body": "hi"} for i in range(100, 250)]
        fake = FakeGitHub(comments=others + [{"id": 5, "user": BOT, "body": REPORT}])
        run(fake)
        self.assertEqual(writes(fake), [("PATCH", "https://api.github.com/repos/acme/app/issues/comments/5")])

    def test_someone_elses_comment_with_the_marker_is_left_alone(self):
        fake = FakeGitHub(comments=[
            {"id": 1, "user": {"login": "mallory", "type": "User"}, "body": REPORT},
            {"id": 2, "user": {"login": "other-app[bot]", "type": "Bot"}, "body": REPORT},
        ])
        run(fake)
        self.assertEqual(writes(fake), [("POST", "https://api.github.com/repos/acme/app/issues/7/comments")])

    def test_a_personal_token_matches_its_own_login(self):
        fake = FakeGitHub(me={"login": "ci-user", "type": "User"},
                          comments=[{"id": 1, "user": BOT, "body": REPORT},
                                    {"id": 3, "user": {"login": "ci-user", "type": "User"}, "body": REPORT}])
        run(fake)
        self.assertEqual(writes(fake), [("PATCH", "https://api.github.com/repos/acme/app/issues/comments/3")])

    def test_a_read_only_token_is_a_warning_not_a_failure(self):
        fake = FakeGitHub(refuse={"POST"})
        code, out = run(fake)
        self.assertEqual(code, 0)
        self.assertIn("::warning::", out)
        self.assertIn("pull-requests: write", out)
        self.assertNotIn(TOKEN, out)

    def test_nothing_is_sent_outside_a_pull_request(self):
        for env in ({"PR_NUMBER": ""}, {"PR_NUMBER": "7; rm -rf /"}, {"GITHUB_TOKEN": ""},
                    {"GITHUB_REPOSITORY": "acme/app/../../x"}, {"GITHUB_API_URL": "http://api.github.com"}):
            with self.subTest(env=env):
                fake = FakeGitHub()
                code, out = run(fake, env=env)
                self.assertEqual((code, fake.calls), (0, []))
                self.assertIn("::warning::", out)

    def test_a_body_over_githubs_limit_is_cut(self):
        fake = FakeGitHub()
        run(fake, body=REPORT + "| x |\n" * 20000)
        body = fake.calls[-1][2]["body"]
        self.assertLessEqual(len(body), 65536)
        self.assertTrue(body.startswith("<!-- aiterprise-scan report -->"))
        self.assertIn("cut", body.rsplit("\n", 2)[-2] + body.rsplit("\n", 2)[-1])

    def test_a_redirect_does_not_carry_the_token(self):
        seen: list[dict] = []

        class Elsewhere(BaseHTTPRequestHandler):
            def do_GET(self):
                seen.append(dict(self.headers))
                self.send_response(200)
                self.end_headers()

            def log_message(self, *args):
                pass

        other = HTTPServer(("127.0.0.1", 0), Elsewhere)

        class Redirects(Elsewhere):
            def do_GET(self):
                self.send_response(302)
                self.send_header("Location", f"http://127.0.0.1:{other.server_port}/steal")
                self.end_headers()

        first = HTTPServer(("127.0.0.1", 0), Redirects)
        for srv in (first, other):
            threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            status, _ = pr_comment._http(TOKEN)("GET", f"http://127.0.0.1:{first.server_port}/user")
        finally:
            for srv in (first, other):
                srv.shutdown()
                srv.server_close()
        self.assertEqual(status, 302)
        self.assertEqual(seen, [])

    def test_a_report_without_the_marker_gets_it(self):
        fake = FakeGitHub()
        run(fake, body="### plain\n")
        self.assertTrue(fake.calls[-1][2]["body"].startswith("<!-- aiterprise-scan report -->\n"))


if __name__ == "__main__":
    unittest.main()
