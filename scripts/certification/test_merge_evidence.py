import json
from pathlib import Path
import tempfile
import unittest
from merge_evidence import combine, REQUIRED_SUITES

class MergeEvidenceTests(unittest.TestCase):
    def make(self, folder, platform, sha, statuses=None):
        obj = {"commit":sha, "gitTreeClean":True, "platform":{"system":platform},
               "status":"passed", "suites":[{"id":i,"status":"passed"} for i in REQUIRED_SUITES]}
        if platform == "Windows": obj["suites"].append({"id":"windows-locked-executable-test", "status":"passed"})
        obj["suites"].extend(statuses or [])
        path = Path(folder)/f"{platform}.json"
        path.write_text(json.dumps(obj))
        return path
    def test_full_same_sha_matrix_passes(self):
        with tempfile.TemporaryDirectory() as d:
            p=[self.make(d,s,"a"*40) for s in ("Windows","Linux","Darwin")]
            self.assertEqual(combine(p)["status"], "passed")
    def test_unmatched_sha_is_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            p=[self.make(d,"Windows","a"*40), self.make(d,"Linux","b"*40), self.make(d,"Darwin","a"*40)]
            self.assertNotEqual(combine(p)["status"], "passed")
    def test_missing_platform_fails_closed(self):
        with tempfile.TemporaryDirectory() as d:
            p=[self.make(d,"Linux","a"*40)]
            self.assertNotEqual(combine(p)["status"], "passed")
    def test_duplicate_platform_fails(self):
        with tempfile.TemporaryDirectory() as d:
            p=self.make(d,"Linux","a"*40)
            with self.assertRaises(ValueError): combine([p,p])
    def test_skipped_test_cannot_pass(self):
        with tempfile.TemporaryDirectory() as d:
            p=[self.make(d,s,"a"*40) for s in ("Windows","Linux","Darwin")]
            payload = json.loads(p[0].read_text())
            payload["suites"] = [v for v in payload["suites"] if v["id"] != "rust-runtime"]
            payload["suites"].append({"id":"rust-runtime","status":"missing"})
            p[0].write_text(json.dumps(payload))
            self.assertNotEqual(combine(p)["status"], "passed")

if __name__=='__main__': unittest.main()
