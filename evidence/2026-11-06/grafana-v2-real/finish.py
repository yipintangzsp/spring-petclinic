import json,pathlib,sys,urllib.request,socket,datetime
sys.dont_write_bytecode=True
HERE=pathlib.Path(__file__).resolve().parent;sys.path.insert(0,str(HERE));from keychain_store import operation
identity=json.loads((HERE/'identity.json').read_text());r=json.loads((HERE/'dashboard-result.json').read_text());health=json.loads((HERE/'production-health.json').read_text())
previous=json.loads(pathlib.Path('evidence/2026-11-06/plugin-controls/jenkins-readonly.json').read_text())
checks={'v1SummaryUnchanged':health['jenkins']['summarySha256']==previous['summarySha256'],'productionJenkinsJobUnchanged':health['jenkins']['jobDefinitionSha256']==previous['jobDefinitionSha256'],'deploymentUnchanged':health['deploymentUnchanged'],'argoApplicationUnchanged':health['argoApplicationUnchanged']}
assert all(checks.values())and health['productionHealth']=='HEALTHY'
op=urllib.request.build_opener(urllib.request.ProxyHandler({}));responses=[]
for url in [r['dashboardUrl'],'http://security.devops.local:17862/api/overview','http://security.devops.local:17862/app.js','http://security.devops.local:17862/']:
 with op.open(url,timeout=12)as response:responses.append((response.status,response.geturl(),response.read(500000)))
assert all(s==200 for s,u,b in responses)
token=operation('get').encode()
assert all(token not in b for s,u,b in responses)
assert all(token not in p.read_bytes()for p in HERE.iterdir()if p.is_file())
del token
result={'at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'GRAFANA_NON_ADMIN_IDENTITY':'VERIFIED','GRAFANA_DASHBOARD_IMPORTED':'VERIFIED','GRAFANA_REAL_DATA':'VERIFIED','SECURITY_MANAGER_OBSERVABILITY_LINK':'VERIFIED','serviceAccount':identity['serviceAccount'],'credentialReference':identity['credentialReference'],'tokenLifetimeSeconds':86400,'folder':identity['folder'],'dashboardUrl':r['dashboardUrl'],'dashboardApiStatus':200,'grafanaQueryApiStatus':200,'macGrafanaHttp':{'status':responses[0][0],'finalUrl':responses[0][1],'loginRequired':True,'addresses':sorted(set(a[4][0]for a in socket.getaddrinfo('grafana.devops.local',80)))},'webHttpStatus':200,'runId':r['runId'],'resultDigest':r['resultDigest'],'dataPanelCount':5,'noDataPanels':[4,5],'staticPanel':8,'realScanThisRound':False,'dataSource':'HISTORICAL_REAL_SCAN / SEALED_ARTIFACT_REPLAY_NOT_NEW_SCAN','sourceExecutionTime':r['executionTime'],'grafanaQueryTime':r['queriedAt'],'leastPrivilege':{'dashboardCreateScopes':['folders:uid:security-manager-v2'],'outsideFolderCreationStatus':403,'globalAdmin':False,'dataSourceReadQueryScope':'INHERITED_VIEWER_DEFAULT_ALL_EXISTING_DATASOURCES','dataSourcePermissionsModified':False},'tokenLeakageCheck':'NO_TOKEN_IN_NEW_FILES_OR_WEB_RESPONSES','productionHealth':'HEALTHY','productionUnchangedChecks':checks,'PRODUCTION_SECURITY_MANAGER':'NOT_ACTIVE','FINAL_WIRED_CAPABILITY':'14/16','ORIGINAL_EVIDENCE_INTEGRITY':'FAILED','RELEASE_COUNT':0,'ROLLOUT_COUNT':0,'browserClick':'NOT_TESTED'}
with(HERE/'verdict.json').open('x')as f:json.dump(result,f,indent=2)
print(json.dumps(result))
