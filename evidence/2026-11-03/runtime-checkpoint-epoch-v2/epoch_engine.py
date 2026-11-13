"""Version 2 engineering epoch verifier. No Policy evaluation or live mutation."""
from pathlib import Path
import json,re,hashlib
from epoch_proxy import digest,validate_samples,sha
def require(ok,code):
 if not ok:raise ValueError('EPOCH_'+code)
def safe_read(root,path):
 require(isinstance(path,str) and not Path(path).is_absolute() and '..' not in Path(path).parts,'UNSAFE_PATH')
 p=(root/path).resolve();require(p.is_relative_to(root.resolve()),'PATH_ESCAPE');return p.read_bytes()
def validate_blocker(b):
 expected={'trivy':('ENVIRONMENT','ENVIRONMENT_BLOCKED'),'defectdojo':('DEPENDENCY','BLOCKED_BY_TRIVY')}
 require(b.get('sourceId') in expected,'BLOCKER_SOURCE');typ,state=expected[b['sourceId']]
 require(b.get('kind')=='EngineeringBlockerReceipt' and b.get('blockerType')==typ and b.get('state')==state,'BLOCKER_KIND')
 require(b.get('runtimeResult') is None and b.get('runtimeResultPresent') is False and b.get('policyResult') is None and b.get('policyEvaluations')==0,'BLOCKER_NOT_POLICY')
 require(b.get('blockerIsNotPolicyResult') is True,'BLOCKER_SCOPE')
 require(not any(k in b for k in ['status','decision','policyDecision','policyStatus']),'BLOCKER_STATUS_SMUGGLING')
 return True
def validate_shape(c):
 required=['checkpointSchemaVersion','epochId','createdAt','gitRevision','pipelineState','v1SummaryIdentity','policyIdentity','canonicalSourceManifest','runtimeCapabilities','blockerReceipts','proxyBaseline','proxySemanticDigest','implementationHashes','historicalContinuity','historicalFailedCheckpointRefs','acceptanceStatus']
 require(all(k in c for k in required),'MISSING_FIELD')
 require(c['checkpointSchemaVersion']==2 and c['epochId'].startswith('runtime-checkpoint-v2-'),'VERSION')
 require(c['historicalContinuity']=='NOT_PROVEN' and c.get('newEpochBaseline')=='CURRENT_STATE_ONLY','HISTORICAL_CONTINUITY')
 require(c.get('oldCheckpointStatus')=='FAILED' and c.get('oldCheckpointReason')=='UNEXPLAINED_PROXY_DRIFT','OLD_FAILURE')
 require(c.get('release')==c.get('rollout')==c.get('newPolicyEvaluations')==0 and not c.get('sameRun16Proven') and not c.get('completeRuntimeArtifactGenerated'),'NO_COMPLETE_OR_MUTATION')
 require(c.get('acceptedWiredCount')==14 and len(c['runtimeCapabilities'])==16,'CAPABILITY_COUNT')
 require(c['acceptanceStatus'] in ['VERIFIED','FAILED'],'ACCEPTANCE')
 require(c['pipelineState'].get('job')=='petclinic-ci' and c['pipelineState'].get('latestBuild')==270 and c['pipelineState'].get('result')=='SUCCESS','PIPELINE')
 require(all(c['runtimeVerdicts'].get(k)=='INCOMPLETE' for k in ['REAL_RUNTIME_FACT_CAPTURE','REAL_POLICY_OWNER','IMMUTABLE_ARTIFACT_RUNTIME','SUMMARY_V2_MIGRATION']),'NO_OVERALL_UPGRADE')
 require(c['runtimeVerdicts'].get('FINAL_WIRED_CAPABILITY')=='14/16','WIRED_COUNT')
 return True
def references(x):
 if isinstance(x,dict):
  if isinstance(x.get('path'),str) and isinstance(x.get('sha256'),str):yield x
  for v in x.values():yield from references(v)
 elif isinstance(x,list):
  for v in x:yield from references(v)
def verify_epoch(root,checkpoint_path,checkpoint_sha,manifest_path,manifest_sha):
 root=Path(root);mb=safe_read(root,manifest_path);require(sha(mb)==manifest_sha,'MANIFEST_DIGEST');m=json.loads(mb)
 require(isinstance(m.get('files'),dict) and m['files'].get(checkpoint_path)==checkpoint_sha,'MANIFEST_CHECKPOINT_BINDING')
 for p,h in m['files'].items():require(sha(safe_read(root,p))==h,'REFERENCE_HASH:'+p)
 cb=safe_read(root,checkpoint_path);require(sha(cb)==checkpoint_sha,'CHECKPOINT_BYTES');c=json.loads(cb);validate_shape(c)
 for r in references(c):require(m['files'].get(r['path'])==r['sha256'],'UNMANIFESTED_REFERENCE:'+r['path'])
 load=lambda r:json.loads(safe_read(root,r['path']))
 old=load(c['historicalFailedCheckpointRefs']['checkpoint']);require(old['authoritativeAcceptance']=='FAILED' and old['authoritativeFailureReason']=='UNEXPLAINED_PROXY_CONFIG_DRIFT','OLD_STATUS')
 oldcheck=load(c['oldCheckpointIntegrity']);require(oldcheck['integrityStatus']=='VERIFIED' and oldcheck['status']=='FAILED' and oldcheck['acceptedWiredCount']==14,'OLD_INTEGRITY')
 require(c['runtimeCapabilities']==old['sources'],'NO_RECEIPT_REBIND')
 require(sum(s['acceptance']=='VERIFIED' for s in c['runtimeCapabilities'])==14,'ACCEPTED_14')
 require(c['policyIdentity']==old['policyBaseline'] and c['canonicalSourceManifest']==old['sourceManifest'],'POLICY_OR_MANIFEST_CHANGED')
 require(c['v1SummaryIdentity']['summarySha256']==old['productionJenkinsIdentity']['summarySha256'] and c['pipelineState']['summarySha256']==c['v1SummaryIdentity']['summarySha256'],'V1_SUMMARY_CHANGED')
 matrix=load(c['sourceHashMatrix']);require(c['implementationHashes']==matrix['implementationHashes'],'SOURCE_MATRIX')
 for p,h in c['implementationHashes'].items():require(m['files'].get(p)==h,'IMPLEMENTATION_HASH:'+p)
 for p,h in matrix['frozenGateHashes'].items():require(m['files'].get(p)==h,'FROZEN_GATE_HASH:'+p)
 for r in c['blockerReceipts']:
  b=load(r['receipt']);validate_blocker(b);require(b['sourceId']==r['sourceId'],'BLOCKER_SOURCE_BINDING')
 require({r['sourceId'] for r in c['blockerReceipts']}=={'trivy','defectdojo'},'BLOCKER_SET')
 contract=load(c['proxyContract']);require(contract['C']['semanticOnlyAllowed'] is False and contract['excludedJsonFields']==contract['excludedDatabaseTables']==[],'NO_SILENT_EXEMPTION')
 samples=[load(r) for r in c['proxyObservations']];result=validate_samples(samples,contract)
 if samples[0].get('status')=='CAPTURED':
  for p,h in samples[0]['immutableProxyFiles'].items():require(sha(Path(p).read_bytes())==h,'LIVE_PROXY_BINARY_HASH')
 require(result==load(c['stabilityEvidence']),'STABILITY_EVIDENCE')
 require(c['proxyBaseline']==c['proxyObservations'][0] and c['proxySemanticDigest']==samples[0].get('proxySemanticDigest'),'BASELINE_BINDING')
 protected=load(c['protectedState']);require(protected['productionUnchanged'] and protected['release']==protected['rollout']==0,'PROTECTED_STATE')
 accepted=result['status']=='VERIFIED' and c['sourcePreservationVerified'] and protected['productionUnchanged']
 require(c['acceptanceStatus']==('VERIFIED' if accepted else 'FAILED'),'FALSE_ACCEPTANCE')
 require(c['resumeContract']['resumeFromWiredCount']==14 and c['resumeContract']['TrivyAutomaticResumeAllowed'] is False and c['resumeContract']['DojoAutomaticResumeAllowed'] is False and c['resumeContract']['SummaryV2Allowed'] is False,'RESUME_SCOPE')
 require(c['resumeContract']['resumeAllowed']==accepted,'RESUME_ACCEPTANCE')
 return {'acceptanceStatus':c['acceptanceStatus'],'integrityStatus':'VERIFIED','epochId':c['epochId'],'historicalContinuity':'NOT_PROVEN','oldCheckpointStatus':'FAILED','acceptedWiredCount':14,'sameRun16Proven':False,'resumeAllowed':accepted,'blockerReceiptCount':2,'policyEvaluations':0,'checkedFiles':len(m['files']),'proxyStability':result}
