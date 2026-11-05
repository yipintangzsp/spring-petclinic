"""Only this chat's bounded tool records. No user messages or unrelated chats."""
from pathlib import Path
import json,datetime,re,os,hashlib,subprocess
O=Path(__file__).resolve().parent;R=O.parents[2];thread=os.environ['CODEX_THREAD_ID'];files=list(Path('/Users/zhangsir/.codex/sessions').rglob('*'+thread+'*.jsonl'));records=[];calls={}
for p in files:
 with p.open()as f:
  for lineNo,line in enumerate(f,1):
   if '2026-11-05T02:' not in line[:80]:continue
   try:x=json.loads(line)
   except ValueError:continue
   ts=x.get('timestamp','');v=x.get('payload',{})
   if not('2026-11-05T02:00'<=ts<'2026-11-05T02:40')or not isinstance(v,dict):continue
   if v.get('type')in['function_call','custom_tool_call']:
    args=str(v.get('arguments',v.get('input','')));tags=re.findall(r'(?:security-manager-v2-loki/(?:run-tests\.py\s+[1-5](?:\s+--loki-only)?|inspect-production\.py\s+(?:before|final)|inspect-observability\.py\s+(?:final|recovery)|health-followup\.py|capture-health-anomaly\.py))',args)
    if tags:
     record={'recordType':'TOOL_DISPATCH_NOT_EXACT_PROCESS_START','timestamp':ts,'sourcePath':str(p),'line':lineNo,'sourceLineSha256':hashlib.sha256(line.encode()).hexdigest(),'callId':v.get('call_id'),'tool':v.get('name'),'commands':sorted(set(tags))};records.append(record);calls[v.get('call_id')]=record
   if v.get('type')in['function_call_output','custom_tool_call_output']and v.get('call_id')in calls:
    text=str(v.get('output',''));records.append({'recordType':'TOOL_RESPONSE_NOT_EXACT_PROBE_TIME','timestamp':ts,'sourcePath':str(p),'line':lineNo,'sourceLineSha256':hashlib.sha256(line.encode()).hexdigest(),'callId':v.get('call_id'),'httpError502Observed':'HTTP Error 502' in text,'sessionIds':re.findall(r'"session_id"\s*:\s*(\d+)',text),'outputSha256':hashlib.sha256(text.encode()).hexdigest()})
legacy=R/'evidence/2026-11-05/security-manager-v2-loki';attempts=[]
for p in sorted(legacy.glob('tests-attempt*.tap')):
 raw=p.read_text();duration=float(re.search(r'^# duration_ms ([0-9.]+)$',raw,re.M).group(1));n=re.search(r'attempt(\d)',p.name).group(1);receipts=[]
 for q in (legacy/('loki-protocol-samples-attempt'+n)).glob('*.json'):
  data=json.loads(q.read_text())
  def walk(v):
   if isinstance(v,dict):
    if v.get('kind')=='LokiCandidateDeliveryReceipt':
     if v.get('timestamp'):receipts.append(v['timestamp'])
     receipts.extend(a['timestamp']for a in v.get('attempts',[])if a.get('timestamp'))
    for vv in v.values():walk(vv)
   elif isinstance(v,list):
    for vv in v:walk(vv)
  walk(data.get('output',{}))
 end=datetime.datetime.fromtimestamp(p.stat().st_mtime,datetime.timezone.utc)
 attempts.append({'attempt':int(n),'nativeNodeDurationMs':duration,'tapWrittenAt':end.isoformat(),'approximateNodeStartFromDurationAndTapMtime':(end-datetime.timedelta(milliseconds=duration)).isoformat(),'startPrecision':'APPROXIMATE; TAP write follows process exit, not an authoritative start event','nativeReceiptInterval':[min(receipts),max(receipts)]if receipts else None,'source':str(p.relative_to(R)),'hostOS':'Darwin','runner':str((legacy/'run-tests.py').relative_to(R))})
ps=subprocess.check_output(['ps','-axo','pid,ppid,etime,%cpu,rss,comm'],text=True);relevant=[l for l in ps.splitlines()if any(t in l.lower()for t in ['qemu','virtual machine','vfkit','utm','node','python'])][:60]
r={'classification':'CURRENT_CHAT_BOUNDED_NATIVE_EXECUTION_RECORDS_AND_LEGACY_RECEIPTS','sessionFileCount':len(files),'records':sorted(records,key=lambda x:x['timestamp']),'attempts':attempts,'currentLocalHost':{'uname':subprocess.check_output(['uname','-a'],text=True).strip(),'nodePath':subprocess.check_output(['which','node'],text=True).strip(),'filesystem':subprocess.check_output(['df','-P',str(R)],text=True),'processMetadataOnly':relevant},'historicalPeakCpuMemoryDisk':'NOT_CAPTURED_UNKNOWN','productionMutations':0}
with(O/'local-execution.json').open('x')as f:json.dump(r,f,indent=2);f.write('\n')
print(json.dumps({'toolRecords':len(records),'attempts':attempts,'localOS':r['currentLocalHost']['uname']}))
