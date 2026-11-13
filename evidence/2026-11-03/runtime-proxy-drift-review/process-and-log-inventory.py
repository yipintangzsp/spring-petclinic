from pathlib import Path
import subprocess,re,json,hashlib,datetime,plistlib
O=Path(__file__).resolve().parent;root=Path('/Users/zhangsir/Library/Application Support/v2rayN');sha=lambda b:hashlib.sha256(b).hexdigest()
def save(n,x):(O/n).write_text(json.dumps(x,ensure_ascii=False,indent=2)+'\n')
p=subprocess.run(['ps','-ww','-axo','pid=,ppid=,lstart=,comm='],capture_output=True,text=True);rows=[]
for line in p.stdout.splitlines():
 m=re.match(r'\s*(\d+)\s+(\d+)\s+(.{24})\s+(.+)$',line)
 if not m:continue
 pid,ppid,start,comm=m.groups();comm=comm.strip()
 if not re.search(r'(?:v2rayN|xray|sing-box|mihomo|[Vv]2ray)',comm):continue
 arg=subprocess.run(['ps','-ww','-p',pid,'-o','command='],capture_output=True,text=True,timeout=5).stdout.strip()
 sanitized=re.sub(r'(?:https?|ss|vmess|vless|trojan)://\S+','<URI_REDACTED>',arg)
 sanitized=re.sub(r'(?i)(password|token|uuid|privatekey)\s*[:= ]\s*\S+',r'\1=<REDACTED>',sanitized)
 # Full lsof only for GUI and its main child; orphan speed-test cores get metadata only.
 main=int(ppid)!=1 or comm.endswith('/MacOS/v2rayN')
 relevant=[];sockets=''
 if main:
  handles=subprocess.run(['lsof','-nP','-a','-p',pid],capture_output=True,text=True,timeout=12)
  relevant=[l for l in handles.stdout.splitlines() if any(k in l for k in ['v2rayN','config.json','guiNDB','LISTEN','cwd'])]
  sockets=subprocess.run(['lsof','-nP','-a','-p',pid,'-iTCP','-sTCP:LISTEN'],capture_output=True,text=True,timeout=10).stdout
 rows.append({'pid':int(pid),'ppid':int(ppid),'startTimeLocal':start.strip(),'executable':comm,'commandLineSanitized':sanitized,'fullCommandLineSha256':sha(arg.encode()),'relevantOpenHandles':relevant,'listenerOutput':sockets,'fullHandlesCollected':main})
save('process-inventory.json',{'readOnly':True,'processes':rows,'processHistoryWriterAttribution':False})
# Inspect launchd configuration metadata; never run or edit launch agents.
agents=[]
for folder in [Path('/Users/zhangsir/Library/LaunchAgents'),Path('/Library/LaunchAgents'),Path('/Library/LaunchDaemons')]:
 if not folder.exists():continue
 for f in folder.glob('*.plist'):
  try:
   b=f.read_bytes();x=plistlib.loads(b);args=x.get('ProgramArguments',[]);program=x.get('Program','');text=f.name+' '+program+' '+' '.join(str(a) for a in args)
   if not re.search('v2ray|xray|proxy|grok|singbox|sing-box',text,re.I):continue
   agents.append({'path':str(f),'sha256':sha(b),'label':x.get('Label'),'program':program,'programArguments':[(a if i==0 or str(a).endswith(('.sh','.py','.plist')) or str(a).startswith('-') else 'VALUE_SHA256:'+sha(str(a).encode())) for i,a in enumerate(args)],'startInterval':x.get('StartInterval'),'startCalendarInterval':x.get('StartCalendarInterval'),'runAtLoad':x.get('RunAtLoad'),'keepAlive':x.get('KeepAlive')})
  except Exception:continue
save('launchd-candidates.json',{'agents':agents,'actions':'READ_ONLY_NO_LOAD_BOOTSTRAP_KICKSTART'})
# Narrow historic log window around BOTH prior changed mtimes.
old=json.load(open(O.parent/'runtime-14-checkpoint-guard-review/observed-protection-drift.json'))['changed'][0]
times=[datetime.datetime.fromtimestamp(old[k]['mtimeNs']/1e9,datetime.timezone.utc) for k in ['before','after']]
windows=[]
for z in times:windows.append({'utc':z.isoformat(),'local':z.astimezone(datetime.timezone(datetime.timedelta(hours=8))).isoformat()})
lines=[];total=0;keywords={}
for file in [root/'guiLogs/2026-11-03.txt']:
 with file.open(errors='replace') as stream:
  for n,l in enumerate(stream,1):
   total+=1
   # App logs timestamp local; retain only around17:15–17:23 (+0800).
   if not re.search(r'2026[-/]11[-/]03[ T]17:(?:1[5-9]|2[0-3]):',l):continue
   event=l.strip()
   event=re.sub(r'(?:https?|ss|vmess|vless|trojan)://\S+','<URI_REDACTED>',event)
   event=re.sub(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b','<IP_REDACTED>',event)
   event=re.sub(r'(?i)(password|token|uuid|privatekey|publickey|server|address|subscription|url)\s*[:=]\s*[^,\s]+',r'\1=<REDACTED>',event)
   if len(event)>700:event=event[:700]+' <TRUNCATED>'
   lines.append({'file':str(file),'line':n,'message':event})
   for k in ['config','save','reload','restart','update','subscription','Start','Stop','CoreConfig','SpeedTest','Process']:
    if k.lower() in l.lower():keywords[k]=keywords.get(k,0)+1
save('application-log-window.json',{'windows':windows,'logTotalLinesScanned':total,'selectedLines':lines[:200],'matchedCount':len(lines),'truncated':len(lines)>200,'keywordCounts':keywords,'redacted':True})
print(json.dumps({'processes':[{'pid':r['pid'],'ppid':r['ppid'],'start':r['startTimeLocal'],'exe':r['executable'],'listeners':r['listenerOutput']} for r in rows],'launchAgents':[{'label':a['label'],'path':a['path'],'interval':a['startInterval']} for a in agents],'logWindowLines':len(lines),'logKeywords':keywords}))
