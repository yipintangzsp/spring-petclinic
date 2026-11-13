from pathlib import Path
import sys,json,hashlib
sys.dont_write_bytecode=True
R=Path('/Users/zhangsir/code/petclinic-platform-20261011');E=R/'evidence/2026-11-03/runtime-checkpoint-epoch-v2';O=R/'evidence/2026-11-03/trivy-guard-dependency-boundary-review';sys.path.insert(0,str(E))
from epoch_proxy import capture
from epoch_engine import verify_epoch
c=json.loads((E/'checkpoint-digest.json').read_text());result=verify_epoch(R,c['checkpointPath'],c['checkpointSha256'],c['integrityManifestPath'],c['integrityManifestSha256']);(O/'checkpoint-preservation.json').write_text(json.dumps(result,indent=2)+'\n')
x=capture('DESIGN_READ_ONLY_CHECK',json.loads((E/'proxy-contract.json').read_text()));(O/'proxy-readonly-current.json').write_text(json.dumps(x,indent=2)+'\n');old=json.loads((E/'samples/T0.json').read_text())
checks={'capture':x['status']=='CAPTURED'}
if checks['capture']:
 for k in ['protected','proxySemanticDigest','immutableProxyFiles']:checks[k]=x[k]==old[k]
 checks['primaryProcessIdentity']=x['processState']['identityDigest']==old['processState']['identityDigest'];checks['runtimeRaw']=x['files']['runtime']['rawSha256']==old['files']['runtime']['rawSha256']
(O/'proxy-preservation.json').write_text(json.dumps({'checks':checks,'passed':all(checks.values()),'agentWrites':0,'agentRestarts':0,'historicalContinuity':'NOT_PROVEN'},indent=2)+'\n');print(json.dumps({'checkpointIntegrity':result['integrityStatus'],'proxyPreservationChecks':checks}))
