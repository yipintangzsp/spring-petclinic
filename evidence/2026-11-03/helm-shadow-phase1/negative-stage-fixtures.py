from pathlib import Path
import tempfile,shutil,subprocess,json,yaml
R=Path(__file__).resolve().parents[3];O=Path(__file__).resolve().parent;results=[]
cases=['missing-digest','malformed-digest','tag-image','selector-mismatch','service-selector-mismatch','invalid-template','privileged-container','missing-request']
for name in cases:
 with tempfile.TemporaryDirectory(prefix='helm-negative-stage-') as td:
  t=Path(td);shutil.copytree(R/'charts',t/'charts');shutil.copytree(R/'infra/helm',t/'infra/helm');(t/'.tools').symlink_to(R/'.tools',target_is_directory=True)
  v=yaml.safe_load((t/'charts/petclinic/values.yaml').read_text());prod=t/'charts/petclinic/values-prod.yaml';phase='render'
  if name=='missing-digest':prod.write_text('image:\n  digest: ""\n')
  if name=='malformed-digest':prod.write_text('image:\n  digest: invalid\n')
  if name=='tag-image':prod.write_text('image:\n  tag: latest\n')
  if name=='selector-mismatch':v['podLabels']['app']='mismatch';phase='validate'
  if name=='service-selector-mismatch':v['service']['selector']['app']='mismatch';phase='validate'
  if name=='invalid-template':(t/'charts/petclinic/templates/bad.yaml').write_text('{{ missingFunction }}')
  if name=='privileged-container':v['securityContext']['privileged']=True;phase='policy'
  if name=='missing-request':del v['resources']['requests']['memory'];phase='validate'
  (t/'charts/petclinic/values.yaml').write_text(yaml.safe_dump(v,sort_keys=False))
  if phase!='render':
   r=subprocess.run(['node','infra/helm/pipeline.mjs','render'],cwd=t,capture_output=True,text=True);assert r.returncode==0,r.stderr[-1000:]
  r=subprocess.run(['node','infra/helm/pipeline.mjs',phase],cwd=t,capture_output=True,text=True);assert r.returncode!=0,name
  status=json.loads((t/'.helm-shadow/status.json').read_text());assert 'FAIL' in status.values(),name
  results.append({'fixture':name,'classification':'REAL_CONTROLLED_LOCAL_OFFLINE_STAGE_EXECUTION','phase':phase,'exitStatus':r.returncode,'pipelineMetadata':status,'productionFilesChanged':False,'temporaryFixtureRemoved':True})
(O/'negative-stage-fixtures.json').write_text(json.dumps(results,indent=2)+'\n');print(json.dumps({'controlledNegativeStages':len(results),'allFailedCorrectly':True,'productionChanges':0}))
