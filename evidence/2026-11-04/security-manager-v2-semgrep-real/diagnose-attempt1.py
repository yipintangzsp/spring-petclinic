"""Read-only inspection of this round's failed disposable package."""
from pathlib import Path
import runpy,json
p=Path(__file__).resolve().parent;api=runpy.run_path(str(p/'inspect-production.py'));root=json.loads((p/'tool-preparation.json').read_text())['workspace']
code="""import pathlib,json
r=pathlib.Path(ROOT)
s=json.loads((r/'outputs/case1-both-clean/candidate-summary.json').read_text())
print(json.dumps({'classification':'REAL_READ_ONLY_FAILED_CONTROLLED_ATTEMPT','missingFrozenDependency':not (r/'package/infra/security/policy/versions/gitleaks-parent.frozen-v1.mjs').exists(),'results':[{k:v.get(k) for k in ['pluginId','executionStatus','policyDecision','failureReason','evaluationCount']} for v in s['pluginResults'] if v['pluginId']in ['gitleaks','semgrep']]}))
"""
x=json.loads(api['remote']('sudo -n python3 -','ROOT='+repr(root)+'\n'+code));api['save']('attempt1-diagnosis.json',x);print(json.dumps(x))
