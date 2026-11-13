from pathlib import Path
import json,collections
O=Path(__file__).resolve().parent;old=json.loads((O.parent/'trivy-infra-repair/image-reference-graph.json').read_text());unknown=[r for r in old['records'] if r['classification']=='D'];harbor=json.loads((O/'harbor-unknown-graph.json').read_text());h={x['digest']:x for x in harbor['artifacts']};local=json.loads((O/'local-registry-graph.json').read_text());remote=json.loads((O/'remote-reference-proof.json').read_text());hidden=json.loads((O/'runtime-hidden-reference-proof.json').read_text());rows=[]
for r in unknown:
 identities={r['id'],*r['repoDigests'],*r['repoTags']};ds={x.split('@')[-1] for x in identities if 'sha256:' in x};proof=[]
 for d in ds:
  if d in h and h[d]['httpStatus']==200 and h[d].get('tags'):proof.append({'type':'LIVE_HARBOR_TAG','digest':d,'tags':h[d]['tags'],'children':h[d].get('references'),'accessories':h[d].get('accessories'),'nullAccessoriesDoesNotProveNoReferrers':True})
 for repo in local['repositoryGraph']:
  for m in repo['manifests']:
   if m.get('digest') in ds or m.get('bodySha256') in ds or (m.get('config') or {}).get('digest')==r['id'] or any(x.get('digest') in ds for x in m.get('children',[])):
    proof.append({'type':'LIVE_LOCAL_REGISTRY_TAG_OR_INDEX','repository':repo['repository'],'tag':m.get('tag'),'digest':m.get('digest'),'children':m.get('children',[]),'config':m.get('config'),'layers':m.get('layers',[]),'subject':m.get('subject')})
 for match in remote['knownImageReferences'][r['id']]:proof.append({'type':'REMOTE_CONFIGURATION_REFERENCE',**match})
 for line in hidden['matchingKnownImageRows']:
  if any(tag.removeprefix('docker.io/') in line for tag in r['repoTags']):proof.append({'type':'LIVE_CONTAINERD_CONTAINER_REFERENCE','row':line})
 verdict='REFERENCED' if proof else 'UNKNOWN';rows.append({'id':r['id'],'repoTags':r['repoTags'],'repoDigests':r['repoDigests'],'verdict':verdict,'safe_delete':False,'proof':proof,'coverageGaps':['No all-history absence proof for GitOps/Jenkins/Ansible/Compose/recovery/SBOM/provenance','No complete reverse referrer/layer ownership proof required for deletion'],'gapsNeverInterpretedAsUnreferenced':True,'registryReclaimEstimate':None,'deleted':False})
counts=dict(collections.Counter(r['verdict'] for r in rows));x={'beforeUnknown':31,'scope':'PER_IMAGE_POSITIVE_REFERENCE_PROOF_OR_EXPLICIT_UNKNOWN','records':rows,'counts':counts,'safeDeleteCount':0,'actualDeletions':0,'provenRegistryReclaimBytes':0,'sharedLayerSizesNotSummed':True};(O/'unknown-image-verdicts.json').write_text(json.dumps(x,indent=2)+'\n');print(json.dumps({'before':31,'after':counts,'safeDelete':0,'remaining':[r['repoTags'] for r in rows if r['verdict']=='UNKNOWN']}))
