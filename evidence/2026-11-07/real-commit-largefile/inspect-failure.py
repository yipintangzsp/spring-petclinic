import pathlib,runpy,shlex,json,sys
sys.dont_write_bytecode=True
p=runpy.run_path('evidence/2026-11-05/gitlab-push-demo/preflight.py')
code=r'''
import pathlib,json
r=pathlib.Path('/var/tmp/security-manager-gitleaks-realcommit-20261107');run='web-9bd5f65d-f047-4261-aa73-55224f3328cb';out={}
for name in ['source-attempt.json',run+'-error.json',run+'-process.json']:
 f=r/'outputs'/name
 if f.exists():out[name]=json.loads(f.read_text())
f=r/'outputs'/run/'artifact/gitleaks.result.json'
if f.exists():
 x=json.loads(f.read_text());out['pluginResult']={k:x.get(k)for k in ['executionStatus','failureReason','evaluationCount','rawReportDigest','factDigest','cleanup','policyDecision']};out['artifactFiles']=[q.name for q in f.parent.iterdir()]
out['sourceWorkspaces']=[p.name for p in(r/'outputs').iterdir()if p.name.startswith('source-web-')];out['scanWorkspaces']=[p.name for p in(r/'outputs').iterdir()if p.name.startswith('scan-')]
print(json.dumps(out))
'''
x=json.loads(p['m']['remote']('sudo -n python3 -c '+shlex.quote(code),timeout=15))
with pathlib.Path('evidence/2026-11-07/real-commit-largefile/failure-inspection.json').open('x')as f:json.dump(x,f,indent=2)
print(json.dumps(x))
