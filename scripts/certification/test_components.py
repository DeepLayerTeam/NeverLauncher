"""Pure fixture/runner tests; real Rust execution is a separate mandatory gate."""
import copy
import hashlib
from pathlib import Path
import tempfile
import unittest

from fault_server import FaultServer, Object
from components_02413 import build_fixture, profile_digest, current_target


class ComponentCertificationFixtureTests(unittest.TestCase):
    def test_snapshot_stays_bound_to_certification_identity(self):
        with FaultServer({"/reserved": Object(b"ready")}) as server:
            objects = server.objects
            doc = build_fixture(server.url, objects, current_target())
            self.assertEqual(doc["projectId"], "certification")
            spec = doc["profileSnapshot"]["spec"]
            self.assertEqual(spec["projectId"], doc["projectId"])
            self.assertEqual(doc["profileSnapshot"]["digest"], profile_digest(spec))
            self.assertEqual(doc["componentCatalog"]["schemaVersion"], "5.0")
            self.assertEqual({r["id"] for r in doc["componentCatalog"]["presets"]}, {"minimal", "optimized", "quality"})
            self.assertTrue(all(item["sha256"] != "a" * 64 for item in doc["files"]))
            self.assertIn("/poison/0", objects)
            self.assertEqual(objects["/files/2"].behavior, "503-once")

    def test_snapshot_digest_is_identity_sensitive(self):
        spec = {"projectId": "certification", "id": "profile", "name": "x", "description": "",
                "loader": "fabric", "preset": "", "isDefault": False}
        digest = profile_digest(spec)
        spec["projectId"] = "other"
        self.assertNotEqual(digest, profile_digest(spec))

if __name__ == "__main__":
    unittest.main()
