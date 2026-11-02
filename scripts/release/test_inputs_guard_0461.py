import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import inputs_guard_0461 as guard

class InputsGuardTests(unittest.TestCase):
    def test_real_frozen_checkout_matches(self):
        baseline=json.loads(guard.BASELINE.read_text())
        guard.verify(baseline, guard.record())
    def test_modified_lockfile_fails_closed(self):
        baseline=json.loads(guard.BASELINE.read_text())
        mutated=json.loads(json.dumps(baseline))
        path='apps/desktop/package-lock.json'
        mutated['files'][path]['sha256']='0'*64
        with self.assertRaisesRegex(ValueError,'input drift'):
            guard.verify(baseline,mutated)
    def test_addition_or_deletion_of_input_fails_closed(self):
        baseline=json.loads(guard.BASELINE.read_text())
        mutated=json.loads(json.dumps(baseline))
        mutated['files'].pop('services/api/go.mod')
        with self.assertRaisesRegex(ValueError,'input drift'):
            guard.verify(baseline,mutated)

if __name__=='__main__':unittest.main()
