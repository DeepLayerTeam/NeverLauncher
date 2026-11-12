import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import inputs_guard as guard

class InputsGuardTests(unittest.TestCase):
    def test_real_frozen_checkout_matches(self):
        baseline=json.loads(guard.BASELINE.read_text())
        guard.verify(baseline, guard.record())
    def test_frozen_baseline_is_the_running_release(self):
        baseline=json.loads(guard.BASELINE.read_text())
        self.assertEqual(baseline['release'], (guard.ROOT/'VERSION').read_text().strip())
        self.assertIn('reproducibility/primary-payload.json',baseline['files'])
        self.assertIn('cli/cmd/launcher/templates/production.zip',baseline['files'])
        self.assertIn('cli/internal/dbmigrate/catalog.zip',baseline['files'])
        self.assertIn('services/api/internal/dbmigrate/sql/0115_imported_file_mirrors.sql',baseline['files'])
        self.assertIn('scripts/release/independent_current.py',baseline['files'])
    def test_version_change_fails_closed(self):
        baseline=json.loads(guard.BASELINE.read_text())
        current=json.loads(json.dumps(baseline))
        current['release']='999.0.0'
        with self.assertRaisesRegex(ValueError, 'Неизвестная исходная база'):
            guard.verify(baseline,current)
    def test_modified_lockfile_fails_closed(self):
        baseline=json.loads(guard.BASELINE.read_text())
        mutated=json.loads(json.dumps(baseline))
        path='apps/desktop/package-lock.json'
        mutated['files'][path]['sha256']='0'*64
        with self.assertRaisesRegex(ValueError,'Изменились входные файлы'):
            guard.verify(baseline,mutated)
    def test_addition_or_deletion_of_input_fails_closed(self):
        baseline=json.loads(guard.BASELINE.read_text())
        mutated=json.loads(json.dumps(baseline))
        mutated['files'].pop('services/api/go.mod')
        with self.assertRaisesRegex(ValueError,'Изменились входные файлы'):
            guard.verify(baseline,mutated)

if __name__=='__main__':unittest.main()
