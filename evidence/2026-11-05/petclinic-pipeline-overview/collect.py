"""Bounded read-only collection. No pipeline execution, token export or production writes."""
import concurrent.futures, datetime, json, runpy, shlex, sys
from pathlib import Path
from urllib.parse import urlencode
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[3]
OUT=Path(__file__).resolve().parent
m=runpy.run_path(str(OUT.parent/'security-manager-v2-loki/inspect-production.py'))
sys.path.insert(0,'/Users/zhangsir/code/evidence/platform-20261011')
from jenkins_control import NODE

GROOVY=r"""
import groovy.json.JsonOutput
import groovy.json.JsonSlurper
import java.security.MessageDigest
def hash={s->MessageDigest.getInstance('SHA-256').digest(s.getBytes('UTF-8')).encodeHex().toString()}
def j=Jenkins.instance.getItemByFullName('petclinic-ci'),b=j.getBuildByNumber(270)
def summaryFile=new File(b.artifactsDir,'.devsecops/security-summary.json')
def summary=new JsonSlurper().parse(summaryFile)
def readReport={name->
 def a=b.artifacts.find{it.relativePath.endsWith('/'+name)}
 a?new JsonSlurper().parse(new File(b.artifactsDir,a.relativePath)):null
}
def provenance=readReport('provenance.json')
def buildProof=readReport('build-attestation-verification.json')
def sourceGate=readReport('source-gate.json')
def sonar=readReport('sonar-quality-gate.json')
def overview=readReport('overview-verification.json')
def candidate=Jenkins.instance.getItemByFullName('petclinic-candidate-build')?.getBuildByNumber(2)
def safeBuild={v->v?[number:v.number,result:v.result?.toString(),timestamp:v.timeInMillis,duration:v.duration,
 causes:v.causes.collect{it.class.simpleName},commit:v.getAction(hudson.plugins.git.util.BuildData)?.lastBuiltRevision?.sha1?.name()]:null}
println(JsonOutput.toJson([
 capturedAt:new Date().format("yyyy-MM-dd'T'HH:mm:ssXXX",TimeZone.getTimeZone('UTC')),
 job:[name:j.fullName,scriptPath:j.definition.scriptPath,remote:j.definition.scm.userRemoteConfigs.collect{it.url},
 branches:j.definition.scm.branches.collect{it.name},definitionSha256:hash(j.configFile.asString()),
 triggers:j.triggers.keySet().collect{it.class.simpleName},lastBuild:safeBuild(j.lastBuild),
 recent:j.builds.take(8).collect{safeBuild(it)}],
 build270:safeBuild(b),
 artifacts:b.artifacts.collect{it.relativePath},
 summaryKeys:summary.keySet(),
 summary:summary,
 summarySha256:hash(summaryFile.text),
 provenance:provenance,buildProof:buildProof,sourceGate:sourceGate,sonar:sonar,overview:overview,
 candidateBuild2:safeBuild(candidate)
]))
"""
def jenkins():
 r=json.loads(m['remote']('sudo -n kubectl exec -i -n ns-devops deploy/github-webhook-relay -- node --max-old-space-size=24 -e '+shlex.quote(NODE),
 json.dumps({'path':'/scriptText','method':'POST','type':'application/x-www-form-urlencoded',
 'body':urlencode({'script':GROOVY}),'timeout':20000}),35))
 if r['status']!=200:raise RuntimeError('Read-only Jenkins status '+str(r['status']))
 data=json.loads(r['body'].split('\n')[0])
 # Restrict the summary projection before storage; no finding values or credentials.
 s=data.pop('summary')
 data['summary']={k:s[k] for k in ['buildNumber','timestamp','commit','image','candidateImage','status','overallStatus','overallDecision','gateDecision','gates','source','qualityGate','sonar','security'] if k in s}
 return data

HOST=r"""
import json,subprocess,urllib.request,urllib.error,datetime
def k(*args):return json.loads(subprocess.check_output(['kubectl',*args],text=True,timeout=15))
def get(url,host=None):
 h={'Host':host} if host else {}
 try:
  with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(urllib.request.Request(url,headers=h),timeout=5) as r:
   body=r.read(256000);ctype=r.headers.get('Content-Type','')
   return {'status':r.status,'json':json.loads(body) if 'application/json'in ctype else None}
 except urllib.error.HTTPError as e:return {'status':e.code}
 except Exception:return {'status':'UNAVAILABLE'}
d=k('-n','petclinic','get','deployment','petclinic','-o','json')
a=k('-n','argocd','get','application','petclinic','-o','json')
nodes=k('get','nodes','-o','json')
ing=k('get','ingress','-A','-o','json')
svcs=k('get','svc','-A','-o','json')
p=k('-n','petclinic','get','pods','-l','app=petclinic','-o','json')
print(json.dumps({
'at':datetime.datetime.now(datetime.timezone.utc).isoformat(),
'deployment':{'ready':d['status'].get('readyReplicas',0),'desired':d['spec']['replicas'],'generation':d['metadata']['generation'],
 'images':[c['image'] for c in d['spec']['template']['spec']['containers']]},
'pods':[{'name':v['metadata']['name'],'node':v['spec'].get('nodeName'),'ready':all(c.get('ready') for c in v['status'].get('containerStatuses',[]))} for v in p['items']],
'argo':{'sync':a['status']['sync']['status'],'health':a['status']['health']['status'],'revision':a['status']['sync']['revision'],
'source':a['spec'].get('source'),'history':[{'id':v['id'],'revision':v.get('revision'),'deployedAt':v.get('deployedAt')} for v in a['status'].get('history',[])[-3:]]},
'nodes':[{'name':n['metadata']['name'],'ready':next(c['status'] for c in n['status']['conditions'] if c['type']=='Ready')} for n in nodes['items']],
'ingresses':[{'name':i['metadata']['name'],'namespace':i['metadata']['namespace'],'hosts':[r.get('host') for r in i['spec'].get('rules',[])]} for i in ing['items']],
'observabilityServices':[{'name':v['metadata']['name'],'namespace':v['metadata']['namespace'],'ports':[p['port'] for p in v['spec']['ports']]} for v in svcs['items'] if any(t in v['metadata']['name'] for t in ['loki','grafana','prometheus'])],
'http':get('http://192.168.64.11/','petclinic.devops.local'),
'harbor':get('http://192.168.64.11/api/v2.0/projects/petclinic/repositories/petclinic/artifacts/'+d['spec']['template']['spec']['containers'][0]['image'].split('@')[-1],'harbor.devops.local'),
'gitlab':get('http://192.168.64.11/api/v4/projects/root%2Fpetclinic-platform','gitlab.devops.local')
}))
"""
if __name__=='__main__':
 with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
  j=pool.submit(jenkins);h=pool.submit(m['remote'],'sudo -n python3 -',HOST)
  x={'jenkins':j.result(),'host':json.loads(h.result())}
 with (OUT/'read-only-sources.json').open('x') as f:json.dump(x,f,indent=2)
 print(json.dumps({'build':x['jenkins']['build270'],'job':x['jenkins']['job'],'summaryKeys':x['jenkins']['summaryKeys'],
 'artifacts':x['jenkins']['artifacts'],'hostKeys':list(x['host']),'gitlabStatus':x['host']['gitlab']['status'],'harborStatus':x['host']['harbor']['status']}))
