import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch
import hashlib
import json
import tempfile

here=Path(__file__).parent
spec=importlib.util.spec_from_file_location('component_matrix_0348',here/'component_matrix_0348.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)

class ComponentMatrixTests(unittest.TestCase):
    def manifest(self):
        return {'files':[{'path':'minecraft.jar'},{'path':'alpha.jar'},{'path':'beta.jar'}],
                'componentCatalog':{'defaultPreset':'minimal',
                    'presets':[{'id':'minimal','components':[]},
                               {'id':'alpha','components':['alpha']}],
                    'components':[{'id':'alpha','files':['alpha.jar'],'dependencies':[],
                                   'version':'1.0.0','visible':True},
                                  {'id':'beta','files':['beta.jar'],'dependencies':[{'id':'alpha'}],
                                   'version':'1.0.0','visible':True}]}}
    def test_named_presets_and_dependency_closure(self):
        ids,files=m.selected_components(self.manifest(),'minimal')
        self.assertEqual(ids,set());self.assertEqual(files,{'minecraft.jar'})
        ids,files=m.selected_components(self.manifest(),'@custom:v1:minimal:+beta')
        self.assertEqual(ids,{'alpha','beta'})
        self.assertEqual(files,{'minecraft.jar','alpha.jar','beta.jar'})
    def test_unsigned_conflict_duplicate_or_invalid_preset_rejected(self):
        for choice in ('other','@custom:v1:minimal:+unknown',
                       '@custom:v1:minimal:+beta,+beta','@custom:v1:minimal:-xyz'):
            with self.subTest(choice=choice),self.assertRaises(ValueError):
                m.selected_components(self.manifest(),choice)
        manifest=self.manifest()
        manifest['componentCatalog']['components'][0]['conflicts']=[{'id':'beta'}]
        with self.assertRaisesRegex(ValueError,'conflicting'):
            m.selected_components(manifest,'@custom:v1:minimal:+beta')
    def test_attestor_rejects_unselected_staged_mod_after_real_selection(self):
        import sys
        sys.path.insert(0,str(here))
        import attestor
        from test_attestor import fixture, dump
        with tempfile.TemporaryDirectory() as d:
            work=Path(d)
            issued=fixture(work)
            signed=json.loads((work/'payload'/'signed-release-manifest.json').read_text())
            pkg=json.loads((work/'payload'/'staged-package-description.json').read_text())
            optional=b'a different optional mod jar'
            mod={'path':'mods/bonus.jar','size':len(optional),'sha256':hashlib.sha256(optional).hexdigest()}
            signed['files'].append(mod);pkg['files'].append(mod)
            signed['componentCatalog']={'schemaVersion':'3.0','digest':'c'*64,
                'presets':[{'id':'minimal','components':[]},{'id':'quality','components':['bonus']}],
                'defaultPreset':'minimal','components':[{'id':'bonus','files':['mods/bonus.jar'],'version':'1.0.0','visible':True}]}
            dump(work/'payload'/'signed-release-manifest.json',signed)
            dump(work/'payload'/'staged-package-description.json',pkg)
            (work/'payload'/'mods'/'bonus.jar').write_bytes(optional)
            native={'status':'ready','files':[{'path':'mods/example.jar','status':'ok'}]}
            sync={'status':'ready','networkDownloads':0,'importedFiles':1,'planSha256':'0'*64}
            dump(work/'component-sync.json',sync)
            dump(work/'native-adoption.json',sync)
            dump(work/'component-verification.json',native)
            component_plan=hashlib.sha256(json.dumps({'catalogDigest':'c'*64,'preset':'minimal',
                'selectedFiles':[('mods/example.jar',signed['files'][0]['sha256'])]},sort_keys=True,
                separators=(',',':')).encode()).hexdigest()
            dump(work/'component-selection.json',{'schemaVersion':'neverlauncher.component-execution.v1',
                 'preset':'minimal','catalogDigest':'c'*64,'resolvedComponentPlanSha256':component_plan,
                 'syncSha256':attestor.sha(work/'component-sync.json'),
                 'nativeVerifySha256':attestor.sha(work/'component-verification.json')})
            identity=json.loads((work/'execution-identity.json').read_text());identity['preset']='minimal'
            identity['resolvedPlanSha256']=hashlib.sha256(json.dumps({'minecraft':signed['minecraft'],
                'runtime':signed['runtime'],
                'fileHashes':sorted((f['path'],f['sha256']) for f in pkg['files']),
                'componentSelection':'minimal','componentPlanSha256':component_plan,
                'componentCatalogDigest':'c'*64},sort_keys=True,separators=(',',':')).encode()).hexdigest()
            dump(work/'execution-identity.json',identity)
            issued['requiredTargets'][0]['preset']='minimal'
            issued['requiredTargets'][0]['resolvedPlanSha256']=identity['resolvedPlanSha256']
            evidence=attestor.verify_local_artifacts(work,issued,'1'*64,'f'*40,'2'*64,'0'*64)
            self.assertEqual(evidence['preset'],'minimal')
            self.assertIn('component-selection.json',evidence['artifactHashes'])
            (work/'client'/'mods'/'bonus.jar').write_bytes(optional)
            with self.assertRaisesRegex(ValueError,'unselected optional component'):
                attestor.verify_local_artifacts(work,issued,'1'*64,'f'*40,'2'*64,'0'*64)

    def test_one_target_success_does_not_certify_other_preset(self):
        import sys
        sys.path.insert(0,str(here))
        import attestor
        targets=[{'id':'one','preset':'minimal','os':'linux','arch':'amd64','authenticationMode':'official'},
                 {'id':'two','preset':'alpha','os':'linux','arch':'amd64','authenticationMode':'official'}]
        grants=[{'runId':str(i),'requiredTargets':targets,'targetMatrixSha256':'a'*64} for i in range(2)]
        class Config:backend='https://example.test';operator_token='private';auth_mode='official'
        def execute(_cfg,_pkg,target,grant):
            if target['id']=='two':raise ValueError('actual Minecraft crashed')
            return {'runId':grant['runId']}
        with patch.object(attestor,'request_json',side_effect=[{'requiredTargets':targets,'targetMatrixSha256':'a'*64,'runId':'first'},grants[1]]),patch.object(attestor,'execute_run',side_effect=execute):
            result=attestor.execute_matrix(Config(),'package')
        self.assertFalse(result['allRequiredTargetsVerified'])
        self.assertEqual([r['status'] for r in result['targets']],['passed','failed'])

if __name__=='__main__':unittest.main()
