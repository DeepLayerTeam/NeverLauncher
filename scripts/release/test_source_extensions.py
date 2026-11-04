"""Check that final source deliveries include executable extension build sources."""
import importlib.util
from pathlib import Path
import tempfile
import unittest
import zipfile

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('source_package', ROOT / 'scripts/release/source-package.py')
source = importlib.util.module_from_spec(spec)
spec.loader.exec_module(source)


class SourceExtensionsTests(unittest.TestCase):
    def test_sdk_examples_port_builder_are_allowlisted(self):
        items = set(source.tracked_files(ROOT))
        for item in ('sdk/java/core/build.sh', 'sdk/java/gravit-compat/build.sh',
                     'examples/extensions/java-host/build.sh',
                     'tools/gravit-port/port.py'):
            self.assertIn(item, items)
        self.assertFalse(any('/build/' in item for item in items if item.startswith(('sdk/', 'examples/'))))

    def test_source_does_not_export_generated_or_secret_files(self):
        self.assertFalse(source.safe_rel('examples/extensions/java-host/build/package/backend/java-host.jar'))
        self.assertFalse(source.safe_rel('sdk/java/core/build/classes/Host.class'))
        self.assertFalse(source.safe_rel('tools/gravit-port/private-key.pem'))
        self.assertTrue(source.safe_rel('examples/extensions/gravit-compat/test-runner.py'))


if __name__ == '__main__':
    unittest.main()
