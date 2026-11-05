"""Jenkins-key-only wrapper. Original fixed scanner/Policy runs exactly once."""
import os,sys,re,json,time,hashlib,secrets,pathlib,subprocess,stat,select
ROOT=pathlib.Path('/var/lib/security-gitops-demo-proofs')
def fail(code):print(json.dumps({'error':code}));raise SystemExit(2)
def digest(v):return hashlib.sha256(json.dumps(v,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()).hexdigest()
if (os.getuid(),os.getgid())!=(24021,24021) or any(g!=24021 for g in os.getgroups()):fail('IDENTITY_REJECTED')
command=os.environ.get('SSH_ORIGINAL_COMMAND','')
m=re.fullmatch(r'(clean-v1|finding-v1) (web-[a-f0-9-]{36})',command)
if not m:fail('FIXED_COMMAND_REQUIRED')
if not select.select([sys.stdin],[],[],2)[0] or sys.stdin.buffer.read(1):fail('INPUT_REJECTED')
st=ROOT.lstat()
if ROOT.resolve()!=ROOT or st.st_uid!=24021 or st.st_gid!=24022 or stat.S_IMODE(st.st_mode)!=0o2750:fail('PROOF_DOMAIN_REJECTED')
try:
 r=subprocess.run(['/usr/bin/python3','-I','/var/tmp/security-manager-gitleaks-v2-linux-20261105/ssh-entry.py'],
  env={'PATH':'/usr/bin:/bin','LANG':'C','SSH_ORIGINAL_COMMAND':command},stdin=subprocess.DEVNULL,capture_output=True,timeout=29)
 if r.returncode!=0 or r.stderr or len(r.stdout)>524288:fail('ORIGINAL_SCAN_REJECTED')
 packet=json.loads(r.stdout);result=packet['result'];facts=result['runtimeFacts']
 body={k:v for k,v in result.items() if k!='resultDigest'}
 if digest(body)!=result['resultDigest'] or packet['runId']!=m[2] or result['runId']!=m[2] or result['executionStatus']!='COMPLETED' or result['evaluationCount']!=1 or packet['policyEvaluationCount']!=1:fail('ORIGINAL_RESULT_INVALID')
 if facts['identity']['uid']!=24021 or facts['tool']['sha256']!='db4d43dd4ab54f047a2d18d210a8d2294e2e5cc26d1e26a299a9675916f5647d':fail('ORIGINAL_RESULT_INVALID')
 now=int(time.time());nonce=secrets.token_hex(24)
 proof={'schemaVersion':1,'kind':'ServerGitleaksGateReceipt','receiptId':nonce,'runId':m[2],
  'scenarioId':packet['scenarioId'],'policyDecision':result['policyDecision'],'resultDigest':result['resultDigest'],
  'factDigest':result['factDigest'],'rawReportDigest':result['rawReportDigest'],'artifactDigest':packet['artifactDigest'],
  'scannerStartedAt':facts['startedAt'],'scannerCompletedAt':facts['completedAt'],
  'scannerExitCode':facts['command']['exitStatus'],'findingsCount':facts['findingsCount'],
  'evaluationCount':result['evaluationCount'],'toolSha256':facts['tool']['sha256'],'issuedAt':now,'expiresAt':now+120}
 proof['receiptDigest']=digest(proof)
 fd=os.open(ROOT/(nonce+'.json'),os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o440)
 with os.fdopen(fd,'w') as f:json.dump(proof,f,sort_keys=True,separators=(',',':'));f.flush();os.fsync(f.fileno())
 packet['gateReceipt']=proof
 print(json.dumps(packet))
except (KeyError,ValueError,OSError,subprocess.TimeoutExpired):fail('GATE_PROOF_EXPORT_FAILED')
