"""Real Node API write-denial tests against synthetic sealed evidence only."""
import importlib.util, json, os, pathlib, subprocess, tempfile, unittest
ROOT=pathlib.Path(__file__).resolve().parents[3]
PRELOAD=ROOT/'infra/observability/testing/frozen-evidence-writes.mjs'
spec=importlib.util.spec_from_file_location('replay',ROOT/'infra/observability/testing/trivy-frozen-replay.py')
replay=importlib.util.module_from_spec(spec);spec.loader.exec_module(replay)
class EvidenceProtection(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(prefix='evidence-protection-fixture-')
        self.parent=pathlib.Path(self.tmp.name).resolve();self.root=self.parent/'copy';self.root.mkdir(mode=0o700)
        (self.root/'.frozen-replay.json').write_text('{"schema":1}')
        self.sealed=self.parent/'sealed.json';self.sealed.write_text('ORIGINAL_SYNTHETIC_EVIDENCE')
    def tearDown(self):self.tmp.cleanup()
    def command(self,code):
        return subprocess.run(['node','--import',str(PRELOAD),'-e',code],cwd=self.root,
          env={**os.environ,'TRIVY_FROZEN_REPLAY_ROOT':str(self.root)},capture_output=True,text=True)
    def denied(self,code):
        r=self.command(code);self.assertNotEqual(r.returncode,0);self.assertIn('FROZEN_',r.stderr)
        self.assertEqual(self.sealed.read_text(),'ORIGINAL_SYNTHETIC_EVIDENCE')
    def test_write_sync_outside(self):self.denied("require('fs').writeFileSync("+json.dumps(str(self.sealed))+",'bad')")
    def test_append_sync_outside(self):self.denied("require('fs').appendFileSync("+json.dumps(str(self.sealed))+",'bad')")
    def test_write_promises_outside(self):self.denied("require('fs/promises').writeFile("+json.dumps(str(self.sealed))+",'bad')")
    def test_open_truncate_outside(self):self.denied("require('fs').openSync("+json.dumps(str(self.sealed))+",'w')")
    def test_remove_outside(self):self.denied("require('fs').rmSync("+json.dumps(str(self.sealed))+")")
    def test_rename_outside(self):self.denied("require('fs').renameSync("+json.dumps(str(self.sealed))+",'inside')")
    def test_symlink_destination_escape(self):
        (self.root/'link').symlink_to(self.parent,target_is_directory=True)
        self.denied("require('fs').writeFileSync('link/sealed.json','bad')")
    def test_named_import_is_protected(self):
        self.denied("import('node:fs').then(({writeFileSync})=>writeFileSync("+json.dumps(str(self.sealed))+",'bad'))")
    def test_private_copy_write_allowed(self):
        r=self.command("require('fs').writeFileSync('inside.json','ok')");self.assertEqual(r.returncode,0,r.stderr)
        self.assertEqual((self.root/'inside.json').read_text(),'ok')
    def test_owned_fd_write_allowed(self):
        r=self.command("const f=require('fs');const d=f.openSync('owner','wx',0o600);f.writeFileSync(d,'ok');f.closeSync(d)")
        self.assertEqual(r.returncode,0,r.stderr);self.assertEqual((self.root/'owner').read_text(),'ok')
    def test_fresh_system_temp_is_registered_but_existing_sealed_path_is_not(self):
        r=self.command("const f=require('fs');const p=f.mkdtempSync('/tmp/evidence-owned-fixture-');f.writeFileSync(p+'/owned','ok');f.rmSync(p,{recursive:true})")
        self.assertEqual(r.returncode,0,r.stderr);self.assertEqual(self.sealed.read_text(),'ORIGINAL_SYNTHETIC_EVIDENCE')
    def test_missing_marker_denied(self):
        (self.root/'.frozen-replay.json').unlink();self.denied("require('fs').writeFileSync('inside','bad')")
    def test_sealed_output_parent_denied(self):
        (self.root/'.guard-boundary-run.json').write_text('{}');(self.root/'evidence-sha256.json').write_text('{}')
        with self.assertRaisesRegex(RuntimeError,'SEALED'):replay.require_fresh_output(self.root,'original-v1')
    def test_existing_output_never_overwritten(self):
        (self.root/'.guard-boundary-run.json').write_text('{}');out=replay.require_fresh_output(self.root,'original-v1')
        (out/'sentinel').write_text('keep')
        with self.assertRaises(FileExistsError):replay.require_fresh_output(self.root,'original-v1')
        self.assertEqual((out/'sentinel').read_text(),'keep')
    def test_historical_parent_without_new_marker_denied(self):
        with self.assertRaisesRegex(RuntimeError,'NEW_EVIDENCE'):replay.require_fresh_output(self.root,'original-v1')
if __name__=='__main__':unittest.main(verbosity=2)
