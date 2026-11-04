"""Offline CLI integrations only. No inherited credentials or production endpoints."""
from pathlib import Path
import json,subprocess,shutil
O=Path(__file__).resolve().parent;catalog=json.load(open('infra/security/manager-v2/fixtures/catalog.json'))
specs=[('java-two','java-web','semgrep,cosign','true','semgrep-pass',0),('python-strict','python-api','semgrep','true','semgrep-pass',0),('master-off','container-service','all','false','semgrep-pass',0),('trivy-blocked','java-web','trivy','true','semgrep-pass',0),('audit-fail','java-web','semgrep','true','semgrep-fail',0),('gitleaks-blocker','java-web','gitleaks,cosign','true','semgrep-pass',1)]
rows=[]
for name,profile,selection,enabled,semgrep,expected in specs:
 inputs={p:{'archiveId':id,'approvedDigest':catalog[id]['sha256']} for p,id in [('semgrep',semgrep),('cosign','cosign-pass'),('gitleaks','gitleaks-pass')]};f=O/(name+'-inputs.json');content=json.dumps(inputs,indent=2)+'\n'
 if f.exists():assert f.read_text()==content
 else:f.write_text(content)
 env={'SECURITY_ENABLED':enabled,'GLOBAL_MODE':'audit','SECURITY_LEVEL':'strict' if profile=='python-api' else 'standard','PROFILE':profile,'POLICY_VERSION':'baseline-v1','PLUGIN_SELECTION':selection}
 args=[shutil.which('node'),'infra/security/manager-v2/cli.mjs','--output',str(O/name),'--project',name,'--run-id',name,'--inputs',str(f)]
 r=subprocess.run(args,env=env,capture_output=True,text=True)
 for suffix,text in [('stdout',r.stdout),('stderr',r.stderr)]:
  with (O/(name+'-cli.'+suffix)).open('x') as stream:stream.write(text)
 assert r.returncode==expected,(name,r.returncode,r.stderr)
 s=json.loads((O/name/'candidate-summary.json').read_text());rows.append({'name':name,'exit':r.returncode,'expectedExit':expected,'profile':s['profile'],'status':s['overallStatus'],'candidateBuildAllowed':s['candidateBuildAllowed'],'promotion':s['promotion'],'policyEvaluations':{p['pluginId']:p['evaluationCount'] for p in s['pluginResults'] if p['evaluationCount']},'pluginResults':[{k:p[k] for k in ['pluginId','executionStatus','policyDecision','resultDigest']} for p in s['pluginResults']],'runtimeEvidence':False})
with (O/'cross-project-smoke.json').open('x') as stream:json.dump(rows,stream,indent=2);stream.write('\n')
print(json.dumps([{k:r[k] for k in ['name','exit','profile','status']} for r in rows]))
