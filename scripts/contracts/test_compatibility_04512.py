import importlib.util
import json
import unittest
from pathlib import Path

MODULE_PATH=Path(__file__).with_name('compatibility_04512.py')
spec=importlib.util.spec_from_file_location('api_compat_04512',MODULE_PATH)
mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod)

class CompatibilityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.base=json.loads(mod.BASE.read_text())
    def test_exact_baseline(self):
        self.assertEqual(mod.check(self.base,self.base),[])
    def test_removed_endpoint(self):
        new=json.loads(json.dumps(self.base));new['paths'].pop('/api/v1/projects')
        self.assertTrue(any('removed endpoint' in e for e in mod.check(self.base,new)))
    def test_required_parameter(self):
        new=json.loads(json.dumps(self.base))
        new['paths']['/api/v1/projects']['get']['parameters']=[{'in':'query','name':'unavailable','required':True,'schema':{'type':'string'}}]
        self.assertTrue(any('new required parameter' in e for e in mod.check(self.base,new)))
    def test_existing_schema_changed(self):
        new=json.loads(json.dumps(self.base)); name=next(iter(new['components']['schemas']))
        new['components']['schemas'][name]['description']='breaking test modification'
        self.assertTrue(any('public schema changed' in e for e in mod.check(self.base,new)))

if __name__=='__main__':unittest.main()
