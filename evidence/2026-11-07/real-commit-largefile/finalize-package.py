import pathlib,runpy,sys,json,shlex,hashlib
sys.dont_write_bytecode=True
p=runpy.run_path('evidence/2026-11-05/gitlab-push-demo/preflight.py');names=['infra/security/manager-v2/ci/source-tree.mjs','infra/security/manager-v2/ci/commit-source-entry.py'];payload={name:pathlib.Path(name).read_text()for name in names}
code=r'''
import json,sys,pathlib,hashlib,subprocess
x=json.load(sys.stdin);r=pathlib.Path('/var/tmp/security-manager-gitleaks-realcommit-20261107');assert not(r/'outputs/source-attempt.json').exists();a=json.loads((r/'approval.json').read_text());assert a['projectId']=='python-fixture'and a['commitSha']=='a69104ba1bf88b74cc57a420888ee692b88c8c48';manifest=json.loads((r/'package-manifest.json').read_text())
for name,text in x.items():
 assert name in ['infra/security/manager-v2/ci/source-tree.mjs','infra/security/manager-v2/ci/commit-source-entry.py'];f=r/'package'/name;assert f.is_file()and f.stat().st_uid==0;f.write_text(text);f.chmod(0o444);manifest[name]=hashlib.sha256(f.read_bytes()).hexdigest()
(r/'package-manifest.json').write_text(json.dumps(manifest));(r/'package-manifest.json').chmod(0o444)
# Only syntax and tool help, never a scan.
for name in ['infra/security/manager-v2/ci/commit-run.mjs','infra/security/manager-v2/ci/source-tree.mjs']:
 q=subprocess.run(['setpriv','--reuid=24021','--regid=24021','--clear-groups','--no-new-privs','node','--check',str(r/'package'/name)],capture_output=True,text=True,timeout=5);assert q.returncode==0
print(json.dumps({'changedPackageFiles':list(x),'sourceAttemptExists':False,'scans':0,'packageManifestUpdated':True}))
'''
print(p['m']['remote']('sudo -n python3 -c '+shlex.quote(code),json.dumps(payload),timeout=20))
