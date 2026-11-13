import json,pathlib,runpy,ast,datetime,urllib.request,socket
HERE=pathlib.Path(__file__).resolve().parent
api=runpy.run_path('evidence/2026-11-05/security-manager-v2-loki/inspect-production.py')
# Reuse the existing bounded, credential-free host health projection.
tree=ast.parse((HERE.parent/'grafana-v2-real'/'health.py').read_text());code=next(ast.literal_eval(node.value)for node in tree.body if isinstance(node,ast.Assign)and any(isinstance(t,ast.Name)and t.id=='code'for t in node.targets))
health=json.loads(api['remote']('sudo -n python3 -',code,75));health['jenkins']=api['jenkins']()
old=json.loads((HERE.parent/'grafana-v2-real'/'production-health.json').read_text())
health['unchanged']={key:health[key]==old[key]for key in ['deploymentSpecSha256','argoSpecSha256','argoRevision','generation','socketMode','pods']}
health['unchanged']['v1Summary']=health['jenkins']['summarySha256']==old['jenkins']['summarySha256']
health['unchanged']['productionJenkinsJob']=health['jenkins']['jobDefinitionSha256']==old['jenkins']['jobDefinitionSha256']
health['health']='HEALTHY'if health['ready']==3 and health['http']==200 and health['argoHealth']=='Healthy'and health['argoSync']=='Synced'and all(n['ready']=='True'for n in health['nodes'])else'DEGRADED'
with(HERE/'production-health.json').open('x')as f:json.dump(health,f,indent=2)
assert health['health']=='HEALTHY'and all(health['unchanged'].values()),'PRODUCTION_STATE_CHANGED'
run=json.loads((HERE/'real-run.json').read_text());grafana=json.loads((HERE/'grafana-query.json').read_text());web=json.loads((HERE/'web-acceptance.json').read_text())
op=urllib.request.build_opener(urllib.request.ProxyHandler({}));base='http://security.devops.local:17862'
with op.open(base+'/api/runs/'+run['runId'],timeout=8)as r:
 assert r.status==200 and json.load(r)==run
with op.open(base+'/',timeout=8)as r:assert r.status==200
s=socket.socket();s.bind(('127.0.0.1',32189));s.close()
l=run['lokiDelivery'];assert l['automatic']and l['state']=='DELIVERED'and l['queryState']=='VERIFIED'
assert grafana['runId']==run['runId']and grafana['resultDigest']==run['resultDigest']and grafana['sourceClassification']=='REAL_CONTROLLED_EXECUTION'
root=pathlib.Path('.devsecops/security-view-runs-v1')/run['runId'];routed=json.loads((root/'loki-delivery/router-receipt.json').read_text());proof=json.loads((root/'loki-delivery/query-proof.json').read_text())
assert routed['lokiDelivery']['httpRequestCount']==1 and proof['matchedEvents']==1
payloads=list((root/'loki-delivery').glob('loki-*/loki-push.json'));assert len(payloads)==1
payload=json.loads(payloads[0].read_text());assert len(payload['streams'])==1 and len(payload['streams'][0]['values'])==1
labels=payload['streams'][0]['stream'];assert not any('run'in k.lower()or'digest'in k.lower()for k in labels)
line=payload['streams'][0]['values'][0][1];assert run['runId']in line and run['resultDigest']in line and 'REAL_CONTROLLED_EXECUTION'in line
result={'at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'AUTO_LOKI_DELIVERY':'VERIFIED','LOKI_QUERY_BACK':'VERIFIED','GRAFANA_NEW_RUN_VISIBLE':'VERIFIED','SECURITY_MANAGER_DELIVERY_STATUS':'VERIFIED','runId':run['runId'],'pluginId':run['pluginId'],'policyDecision':run['policyDecision'],'scannerExitCode':run['scannerExitCode'],'evaluationCount':run['evaluationCount'],'resultDigest':run['resultDigest'],'durationMs':run['durationMs'],'newRealScans':1,'automaticPushRequests':1,'matchedLokiEvents':1,'sourceClassification':'REAL_CONTROLLED_EXECUTION','eventLabels':sorted(labels),'runAndDigestInBodyOnly':True,'rawReportSent':False,'ephemeralChannelClosed':True,'grafanaUrl':grafana['url'],'grafanaDataPanels':grafana['dataPanelCount'],'securityManagerUrl':base+'/#live-validation','pageHttpStatus':200,'recordPersistent':True,'browserClick':'NOT_TESTED','productionHealth':health['health'],'productionUnchanged':True,'productionSecurityManager':'NOT_ACTIVE','finalWiredCapability':'14/16','release':0,'rollout':0}
with(HERE/'verdict.json').open('x')as f:json.dump(result,f,indent=2)
print(json.dumps(result))
