"""net.py against local HTTP servers: what a failure is called, retries, redirects, downloads; and
the rule that a request carrying a key is never sent on to another address."""

import http.server
import json
import socket
import threading
import time
import unittest

from aiterprise_scan import cloudpolicy, credentials, net, secdb

KEY = "aik_live_" + "A" * 36


class Server:
    """A local HTTP server that answers from a script: (status, headers, body) per request, the
    last one repeating. It records what it was sent."""

    def __init__(self, script, delay=0.0):
        self.script = list(script)
        self.delay = delay
        self.seen = []  # (path, lower-cased request headers)
        owner = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def answer(self):
                length = int(self.headers.get("Content-Length") or 0)
                if length:
                    self.rfile.read(length)
                owner.seen.append((self.path, {k.lower(): v for k, v in self.headers.items()}))
                if owner.delay:
                    time.sleep(owner.delay)
                status, headers, body = owner.script[min(len(owner.seen), len(owner.script)) - 1]
                try:
                    self.send_response(status)
                    for name, value in headers.items():
                        self.send_header(name, value)
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                except OSError:
                    pass  # the client gave up waiting (the timeout test): nothing to answer

            do_GET = do_POST = answer

            def log_message(self, *args):
                pass

        self.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.httpd.server_address[1]}"
        threading.Thread(target=self.httpd.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True).start()

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


def answer(status=200, body=b"{}", **headers):
    return status, headers, body


class NetCase(unittest.TestCase):
    def serve(self, *script, delay=0.0):
        server = Server(script, delay)
        self.addCleanup(server.close)
        return server

    def failure(self, call):
        with self.assertRaises(net.NetError) as caught:
            call()
        return caught.exception


class FailureKindTests(NetCase):
    def test_nothing_listening_is_unreachable(self):
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            port = probe.getsockname()[1]
        err = self.failure(lambda: net.request("GET", f"http://127.0.0.1:{port}/x", timeout=5))
        self.assertEqual((err.kind, err.status), ("unreachable", None))

    def test_an_answer_that_comes_too_late_is_a_timeout(self):
        server = self.serve(answer(), delay=1.0)
        err = self.failure(lambda: net.request("GET", server.url + "/x", timeout=0.2))
        self.assertEqual((err.kind, err.status), ("timeout", None))

    def test_an_answer_that_is_not_json_is_invalid(self):
        server = self.serve(answer(body=b"<html>not json</html>"))
        err = self.failure(lambda: net.request("GET", server.url + "/x"))
        self.assertEqual((err.kind, err.status), ("invalid", None))

    def test_an_http_error_keeps_its_status_and_problem_document(self):
        problem = json.dumps({"type": "https://api.aiterprise.net/problems/plan_required", "title": "Plan"}).encode()
        server = self.serve(answer(403, problem))
        err = self.failure(lambda: net.request("GET", server.url + "/x"))
        self.assertEqual((err.kind, err.status, err.problem_type), ("http", 403, "plan_required"))

    def test_an_error_made_without_a_kind_gets_one_from_its_status(self):
        self.assertEqual(net.NetError("no answer").kind, "unreachable")
        self.assertEqual(net.NetError("HTTP 500", status=500).kind, "http")


class RetryTests(NetCase):
    def setUp(self):
        self.slept = []

    def request(self, server, **options):
        return net.request("GET", server.url + "/x", sleep=self.slept.append, **options)

    def test_a_503_is_retried_until_the_answer_comes(self):
        server = self.serve(answer(503), answer(503), answer(body=b'{"ok": true}'))
        self.assertEqual(self.request(server).data, {"ok": True})
        self.assertEqual((len(server.seen), len(self.slept)), (3, 2))
        self.assertTrue(0.5 <= self.slept[0] <= 1.0 <= self.slept[1] <= 1.5, self.slept)  # 0.5 s, then 1 s, + jitter

    def test_retry_after_sets_the_wait_and_is_capped(self):
        server = self.serve(answer(503, **{"Retry-After": "2"}), answer())
        self.request(server)
        self.assertTrue(2.0 <= self.slept[0] <= 2.5, self.slept)
        self.slept.clear()
        server = self.serve(answer(503, **{"Retry-After": "99999"}), answer())
        self.request(server)
        self.assertTrue(net.MAX_RETRY_AFTER <= self.slept[0] <= net.MAX_RETRY_AFTER + 0.5, self.slept)

    def test_when_the_retries_run_out_the_error_is_raised(self):
        server = self.serve(answer(503))
        err = self.failure(lambda: self.request(server, max_retries=2))
        self.assertEqual((err.status, len(server.seen), len(self.slept)), (503, 3, 2))

    def test_a_status_the_caller_does_not_retry_is_raised_at_once(self):
        server = self.serve(answer(429))
        err = self.failure(lambda: self.request(server, retry_on={502, 503}))
        self.assertEqual((err.status, len(server.seen), self.slept), (429, 1, []))

    def test_a_status_the_caller_calls_an_answer_is_returned(self):
        server = self.serve(answer(304, b""))
        self.assertEqual(self.request(server, ok=(304,)).status, 304)


class RedirectTests(NetCase):
    def pair(self):
        final = self.serve(answer(body=b'{"from": "final"}'))
        first = self.serve(answer(302, b"", Location=final.url + "/landed"))
        return first, final

    def test_a_redirect_is_followed_unless_the_caller_says_no_and_urllib_sends_the_headers_on(self):
        first, final = self.pair()
        data = net.request("GET", first.url + "/x", headers={"X-Key": "secret"}).data
        self.assertEqual(data, {"from": "final"})
        self.assertEqual(final.seen[0][1].get("x-key"), "secret")  # why a keyed request must not follow

    def test_a_redirect_that_is_not_followed_is_an_error_and_nothing_is_sent_on(self):
        first, final = self.pair()
        err = self.failure(lambda: net.request("GET", first.url + "/x", headers={"X-Key": "secret"},
                                               follow_redirects=False))
        self.assertEqual((err.kind, err.status), ("redirect", 302))
        self.assertEqual(final.seen, [])


class KeysAreNotSentOnTests(NetCase):
    """SecDB and a cloud are sent the API key. A redirect from either is refused, not followed."""

    def pair(self):
        final = self.serve(answer(body=b'{"plan": "free"}'))
        first = self.serve(answer(302, b"", Location=final.url + "/elsewhere"))
        return first, final

    def test_the_secdb_client_refuses_a_redirect(self):
        first, final = self.pair()
        client = secdb.Client(credentials.Credential("api_key", KEY, "env"), base_url=first.url)
        with self.assertRaises(secdb.SecDBError) as caught:
            client.me()
        self.assertIn("redirect", str(caught.exception))
        self.assertEqual(first.seen[0][1].get("authorization"), f"Bearer {KEY}")
        self.assertEqual(final.seen, [])

    def test_a_cloud_policy_pull_refuses_a_redirect(self):
        first, final = self.pair()
        err = self.failure(lambda: cloudpolicy.TRANSPORT(first.url + "/api/policy/pull",
                                                         {"Authorization": f"Bearer {KEY}"}))
        self.assertEqual(err.kind, "redirect")
        self.assertIn("redirect", cloudpolicy._explain(err))
        self.assertEqual(final.seen, [])


class DownloadTests(NetCase):
    def test_a_download_over_plain_http_is_refused_before_anything_is_sent(self):
        server = self.serve(answer(body=b"bytes"))
        err = self.failure(lambda: net.download(server.url + "/bundle.tar.gz", 1024))
        self.assertEqual(err.kind, "refused")
        self.assertEqual(server.seen, [])


if __name__ == "__main__":
    unittest.main()
