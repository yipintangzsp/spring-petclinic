from pathlib import Path
import json,hashlib,re
O=Path(__file__).resolve().parent;R=O.parents[2];images=json.loads((O/'images.stdout').read_text())['images'];workloads=json.loads((O/'workloads.stdout').read_text());containers=json.loads((O/'containers.stdout').read_text())['containers'];records=[]
# Only known image digests/tags are searched; file contents never enter graph.
text=[]
for top in ['docs','infra','resources','vars','evidence']:
 for p in (R/top).rglob('*'):
  if not p.is_file() or p.is_symlink() or O in p.parents or p.suffix not in ['.json','.md','.yaml','.yml','.mjs','.groovy','.py','.txt']:continue
  if p.stat().st_size>8*1024**2:continue
  if any(x in p.name.lower() for x in ['secret','credential','kubeconfig','private-key']):continue
  try:s=p.read_text()
  except:continue
  text.append((str(p.relative_to(R)),s))
for p in R.glob('Jenkinsfile*'):
 if p.is_file():text.append((p.name,p.read_text()))
for im in images:
 ids={im['id'],*im.get('repoDigests',[]),*im.get('repoTags',[])};digests={s.split('@')[-1] for s in ids if 'sha256:' in s};matches=[]
 for w in workloads:
  refs=[r['image'] for r in w['images']]+[x for x in w.get('imageIDs',[]) if x]
  if any(x in ids or any(d in x for d in digests) for x in refs):matches.append({'kind':w['kind'],'namespace':w['namespace'],'name':w['name'],'uid':w['uid']})
 existing=[c['id'] for c in containers if c.get('imageRef') in ids or c.get('image',{}).get('image') in ids]
 local=[]
 for path,s in text:
  if any(d in s for d in digests) or any(t in s for t in im.get('repoTags',[])):
   local.append({'path':path,'class':'JENKINS_PIPELINE' if 'Jenkinsfile' in path or path.startswith('vars/') else 'ROLLBACK_OR_RECOVERY_DOCUMENT' if path.startswith('docs/') else 'ARCHIVED_MENTION_NOT_PROOF_OF_DEPENDENCY' if path.startswith('evidence/') else 'REPOSITORY_CONFIGURATION','fileSha256':hashlib.sha256(s.encode()).hexdigest()})
 classification='C' if matches or existing or any(r['class']!='ARCHIVED_MENTION_NOT_PROOF_OF_DEPENDENCY' for r in local) else 'D'
 records.append({'id':im['id'],'repoTags':im.get('repoTags',[]),'repoDigests':im.get('repoDigests',[]),'reportedSizeBytes':int(im.get('size',0)),'workloadReferences':matches,'existingContainerReferences':existing,'repositoryReferences':local,'externalCoverage':{'liveHarborTags':'NOT_TESTED_RETAIN_ALL','remoteGitOps':'DISCOVERED_PATHS_NOT_FULLY_SCANNED_RETAIN_ALL','HelmReleaseMetadata':'CLI_UNAVAILABLE_RETAIN_ALL','remoteComposeAndSystemd':'PATHS_AND_DOCKER_MOUNTS_DISCOVERED_NOT_FULLY_RESOLVED_RETAIN_ALL'},'classification':classification,'safe_delete':False,'retentionReason':'Reference present' if classification=='C' else 'Missing full external reference proof','reclaimedBytes':0})
assert len(records)==len(images);(O/'image-reference-graph.json').write_text(json.dumps({'imageCount':len(records),'scope':'CONSERVATIVE_RETENTION_GRAPH_WITH_EXPLICIT_UNKNOWN_EDGES','allImagesRetained':True,'noReferenceAbsenceClaimFromMissingChecks':True,'records':records},indent=2)+'\n');print(json.dumps({'imageCount':len(records),'classC':sum(r['classification']=='C' for r in records),'classD':sum(r['classification']=='D' for r in records),'safeImageDeletions':0}))
