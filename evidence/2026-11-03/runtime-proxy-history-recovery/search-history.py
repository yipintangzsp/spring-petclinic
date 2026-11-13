from pathlib import Path
import json,datetime,re,zipfile,tarfile,os
from history_tools import OLD,NEW,sha,classify,parse,timestamp
O=Path(__file__).resolve().parent;R=Path.cwd();inventory=json.loads((O/'search-path-inventory.json').read_text());records=[];errors=[];archiveRows=[]
def inspect(p,source,entry=None,data=None,mtime=None):
 try:
  s=p.stat();b=p.read_bytes() if data is None else data
  if len(b)>1024**2:return
  mt=mtime or datetime.datetime.fromtimestamp(s.st_mtime,datetime.timezone.utc).isoformat();h=sha(b);shape=False
  try:x=parse(b.decode('utf-8-sig'));shape=isinstance(x,dict) and isinstance(x.get('inbounds'),list) and isinstance(x.get('outbounds'),list)
  except (ValueError,UnicodeError):pass
  records.append({'path':str(p)+('!'+entry if entry else ''),'source':source,'timestamp':mt,'timestampBasis':'filesystem mtime or archive entry metadata; NOT proof of capture time','sha256':h,'size':len(b),'trustLevel':classify(h,mt,source_trusted=source in ['v2rayN_local','repository_backup']),'whyPredatesDrift':'Exact old sealed content hash' if h==OLD else ('mtime earlier only; insufficient authority' if timestamp(mt) and timestamp(mt)<timestamp('2026-11-03T09:20:28Z') else 'No trusted pre-drift binding'),'generatedXrayShape':shape,'rawContentArchived':False})
 except (OSError,ValueError) as e:errors.append({'path':str(p),'errorType':type(e).__name__})
for root,inv in inventory.items():
 for name in inv['paths']:
  p=Path(name);low=name.lower()
  if O in p.parents or '/.codex/sessions/' in name or '/.codex/archived_sessions/' in name:continue
  proxy=('v2ray' in low or 'xray' in low or 'proxy' in low)
  backup=any(k in low for k in ['backup','snapshot','evidence','shared','history','config'])
  config=bool(re.search(r'(config[^/]*\.(json|ya?ml|toml)(\..*)?$|config\.json[^/]*$|\.config\.json.*|.*config.*\.(bak|old|orig|swp|swo|save)$)',p.name,re.I))
  if config and (proxy or (p.name=='config.json' and backup)):
   if p.is_file() and not p.is_symlink() and p.stat().st_size<=1024**2:inspect(p,'v2rayN_local' if '/Application Support/v2rayN/' in name else 'repository_backup')
  if proxy and p.suffix.lower() in ['.zip','.tgz','.gz','.tar'] and p.is_file() and p.stat().st_size<128*1024**2:
   try:
    matches=[]
    if zipfile.is_zipfile(p):
     with zipfile.ZipFile(p) as z:
      for e in z.infolist():
       if 'config' in e.filename.lower() and e.filename.lower().endswith(('.json','.json.bak','.json.old')) and e.file_size<1024**2:
        matches.append(e.filename);inspect(p,'archive_entry',entry=e.filename,data=z.read(e),mtime=datetime.datetime(*e.date_time,tzinfo=datetime.timezone.utc).isoformat())
    elif tarfile.is_tarfile(p):
     with tarfile.open(p) as z:
      for e in z:
       if e.isfile() and 'config' in e.name.lower() and e.name.endswith(('.json','.json.bak','.json.old')) and e.size<1024**2:
        matches.append(e.name);inspect(p,'archive_entry',entry=e.name,data=z.extractfile(e).read(),mtime=datetime.datetime.fromtimestamp(e.mtime,datetime.timezone.utc).isoformat())
    archiveRows.append({'path':name,'matchingConfigEntries':matches,'extractedToFilesystem':False})
   except (OSError,ValueError,tarfile.TarError,zipfile.BadZipFile) as e:errors.append({'path':name,'errorType':type(e).__name__})
# Stream session records. Store only event metadata/digests; no session text or commands.
idx=json.loads((O/'session-search-index.json').read_text());events=[];embedded=[];scan=[]
def strings(x,depth=0):
 if depth>6:return
 if isinstance(x,str):yield x
 elif isinstance(x,dict):
  for v in x.values():yield from strings(v,depth+1)
 elif isinstance(x,list):
  for v in x:yield from strings(v,depth+1)
for name in idx['paths']:
 p=Path(name);count=0;skipped=0;matched=0
 with p.open(errors='replace') as f:
  for no,line in enumerate(f,1):
   count+=1
   if len(line)>8*1024**2:skipped+=1;continue
   if not any(k in line for k in ['v2rayN','xray','binConfigs/config.json',OLD]):continue
   try:x=json.loads(line)
   except ValueError:continue
   matched+=1;at=x.get('timestamp');payload=x.get('payload',{});kind=payload.get('type') if isinstance(payload,dict) else None
   if kind in ['function_call','custom_tool_call']:
    args=payload.get('arguments',payload.get('input',''));text=args if isinstance(args,str) else json.dumps(args);relevant='v2rayN' in text or 'config.json' in text or 'xray' in text
    if relevant:
     cats=[label for label,rx in [('config_reference',r'binConfigs/config\.json'),('write_syntax_in_command',r'write_text|write_bytes|writeFile|shutil\.copy|os\.replace|sed\s+-i|\b(?:cp|mv|tee)\s'),('process_control_syntax',r'pkill|killall|launchctl\s+(?:kickstart|bootstrap|bootout)|osascript|open\s+-a'),('subscription_reference',r'subscription|refresh_managed|gmail_refresh'),('read_or_diagnostic_syntax',r'read_bytes|read_text|lsof|\bps\b|\bstat\b|sha256|journal|log show')] if re.search(rx,text,re.I)]
     events.append({'source':name,'line':no,'timestamp':at,'tool':payload.get('name'),'commandSha256':sha(text.encode()),'categories':cats,'attribution':'WEAK_COMMAND_SYNTAX_ONLY_NOT_A_FILE_WRITE_EVENT','beforeNewMtime':bool(timestamp(at) and timestamp(at)<timestamp('2026-11-03T09:20:28Z'))})
   if kind not in ['function_call_output','custom_tool_call_output']:continue
   # Recover exact config substrings only; a matching old digest is required for authority.
   for s in strings(payload):
    texts=[s]
    if s.lstrip().startswith('{'):
     try:texts+=list(strings(json.loads(s)))
     except ValueError:pass
    for text in texts:
     if not ('"inbounds"' in text and '"outbounds"' in text):continue
     for m in list(re.finditer(r'\{\s*"(?:log|dns|inbounds|outbounds|routing)"',text))[:160]:
      try:value,end=json.JSONDecoder().raw_decode(text[m.start():])
      except ValueError:continue
      if not isinstance(value,dict) or not isinstance(value.get('inbounds'),list) or not isinstance(value.get('outbounds'),list):continue
      raw=text[m.start():m.start()+end]
      digests={sha(v.encode()) for v in [raw,raw+'\n',raw+'\r\n','\ufeff'+raw,'\ufeff'+raw+'\n']}
      embedded.append({'source':name,'line':no,'timestamp':at,'exactSubstringSha256':sha(raw.encode()),'size':len(raw.encode()),'matchesOldIncludingLineEndingVariants':OLD in digests,'matchesCurrentIncludingLineEndingVariants':NEW in digests,'trustLevel':'TRUSTED_PRE_DRIFT' if OLD in digests else 'UNTRUSTED','rawContentArchived':False})
 scan.append({'path':name,'linesScanned':count,'relevantLines':matched,'oversizeLinesSkipped':skipped})
# Shell/session command histories: no replay, no raw command retained.
shell=[]
hist=[Path('/Users/zhangsir/.zsh_history'),Path('/Users/zhangsir/.bash_history')]+[Path(p) for p in inventory['/Users/zhangsir/.zsh_sessions']['paths']]+[Path(p) for p in inventory['/Users/zhangsir/.codex/shell_snapshots']['paths']]
for p in hist:
 if not p.is_file():continue
 found=[]
 for no,line in enumerate(p.open(errors='replace'),1):
  if not re.search(r'v2rayN|xray|binConfigs/config\.json',line,re.I):continue
  tm=re.match(r': (\d+):\d+;',line);at=datetime.datetime.fromtimestamp(int(tm[1]),datetime.timezone.utc).isoformat() if tm else None
  found.append({'line':no,'timestamp':at,'commandSha256':sha(line.encode()),'targetConfigMentioned':'binConfigs/config.json' in line,'writeSyntaxPresent':bool(re.search(r'\b(cp|mv|tee)\b|write_text|write_bytes|sed\s+-i',line)),'classification':'COMMAND_HISTORY_NOT_EXECUTION_PROOF'})
 shell.append({'path':str(p),'matches':found,'rawContentsArchived':False})
save=lambda n,x:(O/n).write_text(json.dumps(x,ensure_ascii=False,indent=2)+'\n')
save('config-candidates.json',{'candidateCount':len(records),'candidates':records,'archives':archiveRows,'errors':errors,'oldMatchingCount':sum(x['sha256']==OLD for x in records),'rawConfigsArchived':False})
save('session-evidence-search.json',{'scans':scan,'toolCommandEvents':events,'embeddedConfigCandidates':embedded,'oldMatchingCount':sum(x['matchesOldIncludingLineEndingVariants'] for x in embedded),'echoesNotIndependentEvidence':True,'historicalWriterConfirmed':False})
save('shell-history-evidence.json',{'sources':shell,'historyReplayed':False,'absenceDoesNotProveNoUserAction':True})
# Retain counts and target-related paths only, not an irrelevant whole-workspace inventory.
for root,x in inventory.items():x['paths']=[p for p in x['paths'] if re.search('v2ray|xray|proxy',p,re.I)]
save('search-path-inventory.json',inventory)
print(json.dumps({'fileCandidates':len(records),'matchingOldFileCopies':sum(x['sha256']==OLD for x in records),'sessionFiles':len(scan),'embeddedCandidates':len(embedded),'matchingOldEmbeddedConfigs':sum(x['matchesOldIncludingLineEndingVariants'] for x in embedded),'toolCommandReferences':len(events),'shellHistoryReferences':sum(len(x['matches']) for x in shell),'errors':len(errors)}))
