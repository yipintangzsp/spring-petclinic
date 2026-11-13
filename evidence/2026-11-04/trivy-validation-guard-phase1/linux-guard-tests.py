"""Controlled Linux Node process tests in an owned /tmp tree; no Jenkins build/config or K8s mutation."""
from pathlib import Path
import subprocess,shlex,tarfile,io,json,hashlib,secrets
O=Path(__file__).resolve().parent;R=O.parents[2]
S=['ssh','-o','BatchMode=yes','-o','ConnectTimeout=6','-o','StrictHostKeyChecking=yes','-o','HostName=192.168.64.11','-o','HostKeyAlias=192.168.1.58','zhang@192.168.1.58']
files=['infra/observability/scanner-db-refresh.mjs','infra/observability/scanner-validation-guard.mjs','infra/observability/testing/scanner-validation-guard.test.mjs']
buf=io.BytesIO()
with tarfile.open(fileobj=buf,mode='w') as t:
 for name in files:t.add(R/name,arcname=name)
run='/tmp/trivy-guard-phase1-'+secrets.token_hex(12)
def remote(command,data=None):
 p=subprocess.run(S+['sudo -n kubectl exec -i -n ns-devops deploy/jenkins -c jenkins -- sh -c '+shlex.quote(command)],input=data,capture_output=True,timeout=50)
 return p
p=remote('umask 077; mkdir '+shlex.quote(run)+' && tar -xf - -C '+shlex.quote(run),buf.getvalue());assert p.returncode==0,'Owned test-source transfer failed'
script='umask 077; cd '+shlex.quote(run)+' || exit 2; mkdir tmp; export TMPDIR='+shlex.quote(run+'/tmp')+'; node --version; uname -m; node --test --test-concurrency=1 infra/observability/testing/scanner-validation-guard.test.mjs; result=$?; if [ "$result" -eq 0 ]; then cd /; rm -rf -- '+shlex.quote(run)+'; fi; exit "$result"'
p=remote(script);(O/'linux-guard-tests.log').write_bytes(p.stdout+p.stderr)
receipt={'classification':'REAL_CONTROLLED_NODE_PROCESS_TESTS_SYNTHETIC_BUDGETS_NOT_TRIVY_REFRESH','exit':p.returncode,'sourceHashes':{f:hashlib.sha256((R/f).read_bytes()).hexdigest() for f in files},'ownedTemporaryRoot':run,'cleanupCommandCompleted':p.returncode==0,'JenkinsBuildTriggered':False,'productionConfigurationChanged':False,'TrivyExecuted':False,'release':0,'rollout':0}
if p.returncode==0:
 check=remote('test ! -e '+shlex.quote(run));receipt['ownedTemporaryRootAbsent']=check.returncode==0
 assert check.returncode==0,'Linux temporary tree cleanup not confirmed'
(O/'linux-guard-tests.json').write_text(json.dumps(receipt,indent=2)+'\n');print(json.dumps(receipt));assert p.returncode==0,'Linux guard tests failed; preserve owned tree for investigation'
