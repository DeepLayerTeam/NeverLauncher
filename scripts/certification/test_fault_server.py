import concurrent.futures
import http.client
import threading
import time
import unittest
from urllib.request import Request, urlopen
from urllib.error import HTTPError

from fault_server import FaultServer, Object


class FaultServerIntegration(unittest.TestCase):
    def fetch(self, url, **headers):
        try:
            with urlopen(Request(url, headers=headers), timeout=4) as stream:
                return stream.status, stream.headers, stream.read()
        except HTTPError as e:
            return e.code, e.headers, e.read()

    def test_interrupted_body_and_resume_206(self):
        data = b"abc123" * 2048
        with FaultServer({"/blob": Object(data, behavior="truncate-once")}) as server:
            with self.assertRaises((http.client.IncompleteRead,)):
                self.fetch(server.url + "/blob")
            partial = server.metrics()["transferredBytes"]
            self.assertGreater(partial, 0)
            status, h, remainder = self.fetch(server.url + "/blob", Range=f"bytes={partial}-", **{"If-Range": '"fixture-v1"'})
            self.assertEqual(status, 206)
            self.assertEqual(h["Content-Range"], f"bytes {partial}-{len(data)-1}/{len(data)}")
            self.assertEqual(data, data[:partial] + remainder)

    def test_changed_etag_forces_full_200(self):
        with FaultServer({"/blob": Object(b"updated")}) as server:
            code, _, body = self.fetch(server.url+"/blob", Range="bytes=3-", **{"If-Range": '"old"'})
            self.assertEqual((code, body), (200, b"updated"))

    def test_wrong_content_range(self):
        with FaultServer({"/blob": Object(b"bytes", behavior="bad-range")}) as server:
            code, headers, _ = self.fetch(server.url+"/blob")
            self.assertEqual(code, 206)
            self.assertNotEqual(headers["Content-Range"], "bytes 0-4/5")

    def test_416_then_good(self):
        with FaultServer({"/blob": Object(b"bytes", behavior="416-once")}) as server:
            self.assertEqual(self.fetch(server.url+"/blob")[0], 416)
            self.assertEqual(self.fetch(server.url+"/blob")[2], b"bytes")

    def test_429_retry_after_seconds(self):
        with FaultServer({"/blob": Object(b"ok", behavior="429-once")}) as server:
            code, headers, _ = self.fetch(server.url+"/blob")
            self.assertEqual(code, 429)
            self.assertEqual(headers["Retry-After"], "0")
            self.assertEqual(self.fetch(server.url+"/blob")[2], b"ok")

    def test_429_retry_after_date(self):
        with FaultServer({"/blob": Object(b"ok", behavior="429-date-once")}) as server:
            code, headers, _ = self.fetch(server.url+"/blob")
            self.assertEqual(code, 429)
            self.assertIn("GMT", headers["Retry-After"])

    def test_503_recover(self):
        with FaultServer({"/blob": Object(b"ok", behavior="503-once")}) as server:
            self.assertEqual(self.fetch(server.url+"/blob")[0], 503)
            self.assertEqual(self.fetch(server.url+"/blob")[0], 200)

    def test_poison_mirror_is_not_expected_bytes(self):
        with FaultServer({"/bad": Object(b"expected", behavior="poison"), "/good": Object(b"expected")}) as server:
            self.assertNotEqual(self.fetch(server.url+"/bad")[2], b"expected")
            self.assertEqual(self.fetch(server.url+"/good")[2], b"expected")

    def test_parallel_measurement_tracks_simultaneous_transfers(self):
        with FaultServer({f"/{i}": Object(b"payload", delay=.12) for i in range(8)}) as server:
            with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
                result = list(pool.map(lambda i: self.fetch(server.url+f"/{i}"), range(8)))
            self.assertTrue(all(code == 200 for code, _, _ in result))
            ordered = sorted(server.metrics()["requests"], key=lambda x: x["durationNs"])
            self.assertEqual(len(ordered), 8)
            self.assertGreaterEqual(server.metrics()["maxActiveOverall"], 2)

    def test_no_unconfigured_resource_exposed(self):
        with FaultServer({"/known": Object(b"ok")}) as server:
            self.assertEqual(self.fetch(server.url+"/unknown")[0], 404)


if __name__ == "__main__":
    unittest.main()
