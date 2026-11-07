# Read-only: no scanner/process/service/file mutation, no credential reads.
import pathlib,json,hashlib,os
r=pathlib.Path('/var/tmp/security-manager-gitleaks-realcommit-20261107');run='web-9bd5f65d-f047-4261-aa73-55224f3328cb';out={'runId':run,'readsOnly':True}
for name in ['source-attempt.json',run+'-error.json',run+'-process.json']:
 f=r/'outputs'/name
 if f.is_file():out[name]=json.loads(f.read_text())
f=r/'outputs'/run/'artifact/gitleaks.result.json'
if f.is_file():
 v=json.loads(f.read_text());out['pluginResult']={k:v.get(k)for k in ['executionStatus','failureReason','evaluationCount','rawReportDigest','factDigest','cleanup','policyDecision']}
 out['artifactFileNames']=sorted(q.name for q in f.parent.iterdir()if q.is_file())
for name in ['infra/security/manager-v2/gitleaks-real.mjs','infra/security/manager-v2/ci/commit-source-entry.py','infra/security/manager-v2/ci/source-snapshot.py']:
 f=r/'package'/name
 if f.is_file():
  b=f.read_bytes();text=b.decode();out[name]={'sha256':hashlib.sha256(b).hexdigest(),'bytes':len(b),'owner':f.stat().st_uid,'mode':oct(f.stat().st_mode&511),'explicitPrivateNestedMkdir':"parent.mkdir(mode=0o700)"in text,'legacyImplicitNestedMkdir':"target.parent.mkdir(parents=True,exist_ok=True)"in text,'scannerMarkerUsesStageOnly':"'scannerStarted':stage=='SCANNER'"in text}
out['remainingSourceDirectories']=[p.name for p in(r/'outputs').iterdir()if p.is_dir()and p.name.startswith(('source-web-','scan-'))]
out['processesOfExecutionUid']=[]
for p in pathlib.Path('/proc').iterdir():
 if not p.name.isdigit():continue
 try:
  if p.stat().st_uid==24021:out['processesOfExecutionUid'].append({'pid':int(p.name),'comm':(p/'comm').read_text().strip()})
 except FileNotFoundError:pass
print(json.dumps(out))
