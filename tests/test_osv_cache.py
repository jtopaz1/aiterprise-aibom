"""OSV advisories and the cache: an offline scan is never an error, and a refresh that fails does not
make old data fresh."""

import tempfile
import unittest
from pathlib import Path
from unittest import mock

from aiterprise_scan import net, vulns
from aiterprise_scan.cache import Cache
from aiterprise_scan.model import Component, ScanResult

QUERY = ("PyPI", "examplepkg", "1.0.0")
ADVISORY = "GHSA-aaaa-bbbb-cccc"
DETAIL = {"id": ADVISORY, "summary": "An example flaw"}
NO_ROUTE = net.NetError("GET https://api.osv.dev/v1/vulns/x failed: no route to host")


class CacheCase(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)


class AdvisoryDetailTests(CacheCase):
    """The id of an advisory is known from the cache; its detail is not there."""

    def judge(self, offline):
        cache = Cache(root=self.root)
        cache.put("osv-query", "|".join(QUERY), [ADVISORY])
        result = ScanResult("repo", "offline" if offline else "online")
        vulns.judge([Component("examplepkg", ecosystem="pypi", version="1.0.0")], result,
                    vulns.OSVClient(cache=cache, offline=offline))
        return result

    def test_offline_it_is_a_note_and_not_an_error(self):
        result = self.judge(offline=True)
        self.assertEqual(result.examined["osv"].errors, 0)
        self.assertTrue(any("1 advisory detail(s)" in note and "not in the cache" in note for note in result.notes),
                        result.notes)
        self.assertFalse(any("could not be fetched" in note for note in result.notes))

    def test_online_a_detail_that_cannot_be_fetched_is_an_error(self):
        with mock.patch.object(net, "request_json", side_effect=NO_ROUTE):
            result = self.judge(offline=False)
        self.assertEqual(result.examined["osv"].errors, 1)
        self.assertTrue(any("1 advisory detail(s) could not be fetched" in note for note in result.notes), result.notes)


class RefreshTests(CacheCase):
    """`ttl=-1`: everything in this cache is already stale."""

    def client(self):
        cache = Cache(root=self.root, ttl=-1)
        cache.put("osv-vuln", ADVISORY, DETAIL)
        return vulns.OSVClient(cache=cache)

    def test_a_refresh_that_fails_uses_the_old_copy_and_does_not_store_it_again(self):
        client = self.client()
        with mock.patch.object(net, "request_json", side_effect=NO_ROUTE), \
                mock.patch.object(Cache, "put") as put:
            self.assertEqual(client.details([ADVISORY]), {ADVISORY: DETAIL})
        put.assert_not_called()

    def test_a_refresh_that_succeeds_is_stored(self):
        client = self.client()
        newer = {**DETAIL, "summary": "Revised"}
        with mock.patch.object(net, "request_json", return_value=newer), \
                mock.patch.object(Cache, "put") as put:
            self.assertEqual(client.details([ADVISORY]), {ADVISORY: newer})
        put.assert_called_once_with("osv-vuln", ADVISORY, newer)


if __name__ == "__main__":
    unittest.main()
