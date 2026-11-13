import pathlib,json,runpy,shlex,sys
sys.dont_write_bytecode=True
p=runpy.run_path('evidence/2026-11-05/gitlab-push-demo/preflight.py')
code=r'''
import pathlib,json
r=pathlib.Path('/var/tmp/security-manager-gitleaks-final-20261107');x=json.loads((r/'outputs/source-attempt.json').read_text());run=x['runId'];f=r/'outputs'/(run+'-stages.jsonl');out={'runId':run,'stages':[json.loads(l)for l in f.read_text().splitlines()]if f.exists()else[]}
for suffix in ['-error.json','-process.json']:
 f=r/'outputs'/(run+suffix)
 if f.exists():out[suffix]=json.loads(f.read_text())
f=r/'outputs'/run/'artifact/gitleaks.result.json'
if f.exists():
 v=json.loads(f.read_text());out['result']={k:v.get(k)for k in ['executionStatus','failureReason','policyDecision','evaluationCount','resultDigest','cleanup','runtimeFacts']}
print(json.dumps(out))
'''
x=json.loads(p['m']['remote']('sudo -n python3 -c '+shlex.quote(code),timeout=15))
with pathlib.Path('evidence/2026-11-07/commit-final/stages.json').open('x')as f:json.dump(x,f,indent=2)
print(json.dumps(x))
