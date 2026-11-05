import subprocess,json,datetime,re,hashlib
now=lambda:datetime.datetime.now(datetime.timezone.utc).isoformat();r={'classification':'BOUNDED_READ_ONLY_JOURNAL','startedAt':now(),'windowStart':'2026-11-05T02:05:00Z','windowEnd':'2026-11-05T02:45:00Z','queries':[],'productionMutations':0}
base=['journalctl','--utc','--since','2026-11-05 02:05:00 UTC','--until','2026-11-05 02:45:00 UTC','--no-pager','-o','json']
pattern='oom|out of memory|killed process|PLEG|[Nn]ot[Rr]eady|not ready|timed out|timeout|deadline|containerd|runtime|probe|failed|[Ee]rror|unreachable|slow|heartbeat|lease|readiness|liveness|pressure|blocked for|soft lockup|clock|suspend|resume|syncing|Unable to register'
def clean(s):
 s=re.sub(r'(?i)(authorization[:=]\s*(?:Bearer|Basic|Token)\s+)\S+',r'\1[REDACTED]',str(s));s=re.sub(r'(?i)((?:password|passwd|api_token|access_token|K3S_TOKEN|token)=)[^\s,;]+',r'\1[REDACTED]',s);s=re.sub(r'(https?://)[^/@\s]+:[^/@\s]+@',r'\1[REDACTED]@',s);return s[:5000]
for name,extra,n in [('kernel',['-k'],1000),('k3s',['-u','k3s'],4000),('containerd',['-u','containerd'],1000)]:
 args=base+extra+['-g',pattern,'-n',str(n)];at=now()
 try:p=subprocess.run(args,capture_output=True,text=True,timeout=40)
 except subprocess.TimeoutExpired:r['queries'].append({'name':name,'startedAt':at,'error':'TIMEOUT','timeoutSeconds':40});continue
 rows=[]
 for line in p.stdout.splitlines():
  try:x=json.loads(line)
  except ValueError:continue
  raw=x.get('__REALTIME_TIMESTAMP');rows.append({'realtimeMicroseconds':raw,'timestamp':datetime.datetime.fromtimestamp(int(raw)/1e6,datetime.timezone.utc).isoformat()if raw else None,'monotonicMicroseconds':x.get('__MONOTONIC_TIMESTAMP'),'bootId':x.get('_BOOT_ID'),'unit':x.get('_SYSTEMD_UNIT'),'pid':x.get('_PID'),'priority':x.get('PRIORITY'),'message':clean(x.get('MESSAGE',''))})
 r['queries'].append({'name':name,'command':args,'startedAt':at,'completedAt':now(),'exit':p.returncode,'stderr':p.stderr[:1000],'rowCount':len(rows),'cap':n,'mayBeTruncated':len(rows)>=n,'rows':rows})
r['unitStatus']={}
for name in ['k3s','k3s-agent','containerd','k3s-ssh-tunnel']:
 p=subprocess.run(['systemctl','show',name,'-p','LoadState','-p','ActiveState','-p','SubState','-p','MainPID','-p','NRestarts','-p','ActiveEnterTimestamp','-p','ExecMainStartTimestamp'],capture_output=True,text=True,timeout=5);r['unitStatus'][name]={'exit':p.returncode,'stdout':p.stdout,'stderr':p.stderr[:500]}
r['completedAt']=now();print(json.dumps(r))
