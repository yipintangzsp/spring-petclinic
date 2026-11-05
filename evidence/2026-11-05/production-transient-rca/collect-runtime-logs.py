import subprocess,json,datetime,urllib.request,urllib.error,urllib.parse,re
now=lambda:datetime.datetime.now(datetime.timezone.utc).isoformat();start='2026-11-05T02:05:00Z';end='2026-11-05T02:45:00Z';enddt=datetime.datetime.fromisoformat(end.replace('Z','+00:00'));r={'classification':'BOUNDED_KUBERNETES_GET_LOGS_AND_LOKI_READ_ONLY','startedAt':now(),'start':start,'end':end,'podLogs':[],'lokiQueries':[],'productionMutations':0}
def clean(s):
 s=re.sub(r'(?i)(authorization[:=]\s*(?:Bearer|Basic|Token)\s+)\S+',r'\1[REDACTED]',s);s=re.sub(r'(?i)((?:password|passwd|api_token|access_token|K3S_TOKEN)\s*[:=]\s*)[^\s,;]+',r'\1[REDACTED]',s);return re.sub(r'(https?://)[^/@\s]+:[^/@\s]+@',r'\1[REDACTED]@',s)[:5000]
def kget(p):return subprocess.check_output(['kubectl','--request-timeout=8s','get','--raw',p],text=True,stderr=subprocess.PIPE,timeout=12)
pods=json.loads(kget('/api/v1/pods'))['items']
selected=[p for p in pods if p['metadata']['namespace']=='petclinic'and p['metadata'].get('labels',{}).get('app')=='petclinic'or p['metadata']['namespace']=='argocd'and any(w in p['metadata']['name']for w in ['application-controller','repo-server'])or p['metadata']['namespace']=='kube-system'and p['metadata'].get('labels',{}).get('app.kubernetes.io/name')=='traefik']
for p in selected:
 ns=p['metadata']['namespace'];name=p['metadata']['name']
 for c in p['spec']['containers']:
  for previous in [False,True]:
   q={'container':c['name'],'sinceTime':start,'timestamps':'true','limitBytes':'1572864','tailLines':'4000'}
   if previous:q['previous']='true'
   path='/api/v1/namespaces/'+ns+'/pods/'+name+'/log?'+urllib.parse.urlencode(q);at=now()
   try:
    body=kget(path);lines=body.splitlines();kept=[];outside=0
    for line in lines:
     stamp=line.split(' ',1)[0]
     try:t=datetime.datetime.fromisoformat(stamp.replace('Z','+00:00'))
     except ValueError:continue
     if datetime.datetime.fromisoformat(start.replace('Z','+00:00'))<=t<=enddt:kept.append(clean(line))
     else:outside+=1
    r['podLogs'].append({'namespace':ns,'pod':name,'uid':p['metadata']['uid'],'container':c['name'],'previous':previous,'requestedAt':at,'rawPath':path,'receivedBytes':len(body.encode()),'receivedLines':len(lines),'possiblyCapped':len(lines)>=4000 or len(body.encode())>=1572864,'outOfWindowLinesOmitted':outside,'windowLines':kept})
   except Exception as e:r['podLogs'].append({'namespace':ns,'pod':name,'container':c['name'],'previous':previous,'requestedAt':at,'errorClass':type(e).__name__,'status':'UNAVAILABLE_NOT_EMPTY'})
traefik=json.loads(kget('/apis/apps/v1/namespaces/kube-system/deployments/traefik'));r['traefikConfigProjection']={'generation':traefik['metadata']['generation'],'uid':traefik['metadata']['uid'],'observedAt':now(),'flags':[a for c in traefik['spec']['template']['spec']['containers']for a in c.get('args',[])if re.match(r'--(?:accesslog|log\.|metrics\.|entrypoints\.)',a,re.I)]}
origin='http://10.43.7.197:3100';op=urllib.request.build_opener(urllib.request.ProxyHandler({}))
for label,query in [('petclinic','{namespace="petclinic",container="petclinic"}'),('traefik','{namespace="kube-system",container="traefik"}'),('argo-controller','{namespace="argocd",container="argocd-application-controller"} |~ "(?i)petclinic|error|timeout|unavailable|connection refused"'),('argo-repo','{namespace="argocd",container="argocd-repo-server"} |~ "(?i)error|timeout|unavailable|starting|listening|SIGTERM"')]:
 params={'query':query,'start':start,'end':end,'limit':'2000','direction':'forward'};at=now()
 try:
  res=op.open(origin+'/loki/api/v1/query_range?'+urllib.parse.urlencode(params),timeout=15);b=res.read(4*1024*1024+1);assert len(b)<=4*1024*1024,'RESPONSE_CAP';data=json.loads(b);streams=data.get('data',{}).get('result',[]);entries=[{'stream':s['stream'],'nanosecondTimestamp':v[0],'line':clean(v[1])}for s in streams for v in s.get('values',[])];r['lokiQueries'].append({'name':label,'query':query,'requestedAt':at,'httpStatus':res.status,'responseStatus':data.get('status'),'resultType':data.get('data',{}).get('resultType'),'entryCount':len(entries),'possiblyCapped':len(entries)>=2000,'entries':entries,'stats':data.get('data',{}).get('stats',{}).get('summary')})
 except Exception as e:r['lokiQueries'].append({'name':label,'query':query,'requestedAt':at,'errorClass':type(e).__name__,'httpStatus':getattr(e,'code',None),'status':'UNAVAILABLE_NOT_EMPTY'})
r['completedAt']=now();print(json.dumps(r))
