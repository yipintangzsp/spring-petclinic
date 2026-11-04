import subprocess,json,datetime,time
assert datetime.datetime.now(datetime.timezone.utc)<datetime.datetime(2026,11,4,5,4,tzinfo=datetime.timezone.utc)
def run(c,**kw):
 r=subprocess.run(c,capture_output=True,text=True,timeout=kw.get('timeout',20));assert r.returncode==0,r.stderr[-1000:];return r.stdout
apps=json.loads(run(['sudo','-n','kubectl','get','applications','-A','-o','json']))
assert not [a['metadata']['name'] for a in apps['items'] for r in a.get('status',{}).get('resources',[]) if r.get('kind')=='Deployment' and r.get('name')=='jenkins' and r.get('namespace')=='ns-devops'],'GITOPS_OWNERSHIP_REQUIRES_REVIEW'
d=json.loads(run(['sudo','-n','kubectl','get','deployment','jenkins','-n','ns-devops','-o','json']));assert d['metadata']['uid']=='f2540d48-0f1e-4791-b277-0432c223c98f';assert d['spec']['template']['spec'].get('securityContext',{})=={}
patch=[{'op':'test','path':'/metadata/uid','value':d['metadata']['uid']},{'op':'test','path':'/metadata/resourceVersion','value':d['metadata']['resourceVersion']},{'op':'add','path':'/spec/template/spec/securityContext/supplementalGroups','value':[988]}]
cmd=['sudo','-n','kubectl','patch','deployment','jenkins','-n','ns-devops','--type=json','-p',json.dumps(patch)]
dry=run(cmd+['--dry-run=server','-o','json']);after=json.loads(dry);expected=json.loads(json.dumps(d['spec']));expected['template']['spec']['securityContext']['supplementalGroups']=[988];assert after['spec']==expected
started=datetime.datetime.now(datetime.timezone.utc).isoformat();result=run(cmd);roll=run(['sudo','-n','kubectl','rollout','status','deployment/jenkins','-n','ns-devops','--timeout=300s'],timeout=310)
identity=run(['sudo','-n','kubectl','exec','-n','ns-devops','deploy/jenkins','--','id']);assert '988'in identity
api=run(['sudo','-n','kubectl','exec','-n','ns-devops','deploy/jenkins','--','docker','info','--format','{{.ID}}']);assert api.strip()=='4616ba22-4e70-4b96-8e66-6a3a4d756cb2'
print(json.dumps({'startedAt':started,'readyAt':datetime.datetime.now(datetime.timezone.utc).isoformat(),'patch':patch,'serverDryRunOnlyExpectedChange':True,'gitopsApplicationClaimingJenkins':False,'patchResult':result,'rolloutStatus':roll,'identity':identity,'daemonID':api,'jenkinsPodReplacement':1,'petclinicRollout':0},indent=2))
