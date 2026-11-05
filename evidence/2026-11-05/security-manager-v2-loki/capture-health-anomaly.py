"""Read-only anomaly investigation, never fix or restart production services."""
from pathlib import Path
import runpy,json
O=Path(__file__).resolve().parent;a=runpy.run_path(str(O/'inspect-production.py'))
code=r'''
import subprocess,json,datetime,urllib.request,urllib.error
k=lambda args:json.loads(subprocess.check_output(['kubectl']+args,text=True,timeout=25))
r={'at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'classification':'READ_ONLY_HEALTH_ANOMALY','mutations':0}
r['nodes']=[{'name':n['metadata']['name'],'conditions':n['status']['conditions']}for n in k(['get','nodes','-o','json'])['items']]
r['leases']=[{'name':n['metadata']['name'],'renewTime':n['spec'].get('renewTime')}for n in k(['-n','kube-node-lease','get','lease','-o','json'])['items']]
r['pods']={}
for ns in ['petclinic','monitoring']:
 r['pods'][ns]=[{'name':p['metadata']['name'],'node':p['spec'].get('nodeName'),'phase':p['status'].get('phase'),'conditions':p['status'].get('conditions'),'containers':[{'name':s['name'],'ready':s['ready'],'restartCount':s['restartCount'],'state':s['state'],'lastState':s.get('lastState')}for s in p['status'].get('containerStatuses',[])]}for p in k(['-n',ns,'get','pods','-o','json'])['items']if ns=='petclinic'or any(x in p['metadata']['name']for x in ['loki','alloy','grafana'])]
r['events']=[{'namespace':e['metadata']['namespace'],'object':e.get('involvedObject',{}).get('name'),'reason':e.get('reason'),'lastTimestamp':e.get('lastTimestamp'),'count':e.get('count'),'message':e.get('message','')[:500]}for e in k(['get','events','-A','-o','json'])['items']if (e.get('involvedObject',{}).get('name','').startswith(('petclinic-','loki-'))or e.get('reason')in ['NodeNotReady','NodeReady','SystemOOM','Evicted'])][-60:]
r['endpoints']={ns:k(['-n',ns,'get','endpointslice','-l','kubernetes.io/service-name='+svc,'-o','json'])['items']for ns,svc in [('petclinic','petclinic'),('monitoring','loki')]}
r['http']=[]
for url,host in [('http://192.168.64.11/','petclinic.devops.local'),('http://loki.monitoring.svc.cluster.local:3100/ready',None)]:
 try:
  q=urllib.request.Request(url,headers={'Host':host}if host else{});res=urllib.request.build_opener(urllib.request.ProxyHandler({})).open(q,timeout=6);status=res.status;res.close()
 except urllib.error.HTTPError as e:status=e.code
 except (urllib.error.URLError,TimeoutError):status='UNREACHABLE'
 r['http'].append({'url':url,'host':host,'status':status})
print(json.dumps(r))
'''
x=json.loads(a['remote']('sudo -n python3 -',code,120));a['save']('health-anomaly.json',x);print(json.dumps({'nodes':[{ 'name':n['name'],'conditions':[{k:c[k]for k in ['type','status','reason']}for c in n['conditions']]}for n in x['nodes']],'pods':x['pods'],'http':x['http']}))
