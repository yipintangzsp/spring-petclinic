"""Read-only current-state capture and fail-closed epoch proxy validator.
Only public settings and aggregate private-content digests are emitted.
No live config mutation, command execution through config, or DB exports.
"""
from pathlib import Path
import json,hashlib,datetime,sqlite3,subprocess,re,time,ipaddress
ROOT=Path('/Users/zhangsir/Library/Application Support/v2rayN')
def sha(b):return hashlib.sha256(b).hexdigest()
def parse(b):
 def pairs(items):
  x={}
  for k,v in items:
   if k in x:raise ValueError('DUPLICATE_JSON_KEY')
   x[k]=v
  return x
 return json.loads(b,object_pairs_hook=pairs,parse_constant=lambda _:(_ for _ in ()).throw(ValueError('NONFINITE_JSON')))
def canonical(x):return json.dumps(x,sort_keys=True,ensure_ascii=False,separators=(',',':'),allow_nan=False).encode()
def digest(x):return sha(canonical(x))
def filemeta(p,b):
 s=p.stat();return {'path':str(p),'rawSha256':sha(b),'bytes':len(b),'mtimeNs':s.st_mtime_ns,'inode':s.st_ino,'ownerUid':s.st_uid,'groupGid':s.st_gid,'modeOctal':oct(s.st_mode & 0o777)}
def typed(v):
 if v is None:return ['null']
 if isinstance(v,bytes):return ['blob',sha(v)]
 return [type(v).__name__,v]
def database_snapshot(p):
 # Existing journal_mode is delete. mode=ro + query_only + read transaction;
 # no PRAGMA journal_mode mutation, backup, export, private key access or writes.
 c=sqlite3.connect(p.as_uri()+'?mode=ro',uri=True,timeout=2)
 try:
  c.execute('PRAGMA query_only=ON');c.execute('BEGIN')
  mode=c.execute('PRAGMA journal_mode').fetchone()[0]
  if mode!='delete':raise ValueError('UNSUPPORTED_DB_JOURNAL_MODE')
  schema=c.execute('SELECT type,name,tbl_name,sql FROM sqlite_master ORDER BY type,name,tbl_name').fetchall()
  tables=[]
  for name in [r[1] for r in schema if r[0]=='table']:
   quoted='"'+name.replace('"','""')+'"';cols=c.execute('PRAGMA table_info('+quoted+')').fetchall()
   sql=next(r[3] or '' for r in schema if r[0]=='table' and r[1]==name)
   with_rowid='WITHOUT ROWID' not in sql.upper()
   rows=sorted(digest([typed(v) for v in row]) for row in c.execute('SELECT '+('rowid,*' if with_rowid else '*')+' FROM '+quoted))
   tables.append({'table':name,'columns':[r[1] for r in cols],'hiddenRowIdProtected':with_rowid,'rowCount':len(rows),'allRowsDigest':digest(rows),'columnMetadataDigest':digest(cols)})
  result={'journalMode':mode,'schemaDigest':digest(schema),'tables':tables,'consistentReadTransaction':True,'allTablesProtected':True,'excludedTables':[]}
  result['semanticDigest']=digest({'schemaDigest':result['schemaDigest'],'tables':tables,'journalMode':mode})
  c.rollback();return result
 finally:c.close()
def endpoint_loopback(n):
 try:return ipaddress.ip_address(n.rsplit(':',1)[0].strip('[]')).is_loopback
 except ValueError:return False
def process_state():
 p=subprocess.run(['ps','-ww','-axo','pid=,ppid=,lstart=,comm='],capture_output=True,text=True,timeout=8)
 if p.returncode:raise ValueError('PROCESS_INVENTORY_UNAVAILABLE')
 processes=[]
 for line in p.stdout.splitlines():
  m=re.match(r'\s*(\d+)\s+(\d+)\s+(.{24})\s+(.+)$',line)
  if not m:continue
  pid,ppid,start,exe=m.groups();exe=exe.strip()
  if not (exe.endswith('/xray') or exe.endswith('/MacOS/v2rayN')):continue
  a=subprocess.run(['ps','-ww','-p',pid,'-o','command='],capture_output=True,text=True,timeout=3).stdout.strip()
  main=bool(re.search(r'(?:-config|-c)\s+(?:\S*/)?config\.json(?:\s|$)',a))
  gui=exe.endswith('/MacOS/v2rayN')
  if not (main or gui):continue
  expected=str(ROOT/'bin/xray/xray') if main else '/Applications/v2rayN.app/Contents/MacOS/v2rayN'
  if exe!=expected:raise ValueError('UNAPPROVED_PRIMARY_EXECUTABLE')
  # main args contain no secrets in the approved shape; full bytes remain bound by digest.
  safe=re.sub(r'(?:https?|vmess|vless|trojan|ss)://\S+','<URI_REDACTED>',a)
  safe=re.sub(r'(?i)(password|token|uuid|privatekey)\s*[:= ]\s*\S+',r'\1=<REDACTED>',safe)
  processes.append({'role':'primary-xray' if main else 'gui','pid':int(pid),'ppid':int(ppid),'startTimeLocal':start.strip(),'executable':exe,'commandLineSanitized':safe,'commandSha256':sha(a.encode())})
 main=[x for x in processes if x['role']=='primary-xray'];gui=[x for x in processes if x['role']=='gui']
 if len(main)!=1 or len(gui)!=1 or main[0]['ppid']!=gui[0]['pid']:raise ValueError('PRIMARY_PROCESS_BINDING_UNKNOWN')
 if not re.search(r'(?:-config|-c)\s+config\.json(?:\s|$)',main[0]['commandLineSanitized']):raise ValueError('CONFIG_PATH_BINDING_UNKNOWN')
 cwd=subprocess.run(['lsof','-nP','-a','-p',str(main[0]['pid']),'-d','cwd','-Fn'],capture_output=True,text=True,timeout=5)
 if cwd.returncode or 'n'+str(ROOT/'binConfigs') not in cwd.stdout.splitlines():raise ValueError('CORE_WORKING_DIRECTORY_UNKNOWN')
 main[0]['workingDirectory']=str(ROOT/'binConfigs')
 main[0]['startEpochSeconds']=time.mktime(time.strptime(main[0]['startTimeLocal'],'%a %b %d %H:%M:%S %Y'))
 p=subprocess.run(['lsof','-nP','-a','-c','xray','-iTCP','-sTCP:LISTEN','-Fpcn'],capture_output=True,text=True,timeout=8)
 if p.returncode:raise ValueError('LISTENERS_UNAVAILABLE')
 listeners=[];pid=None
 for l in p.stdout.splitlines():
  if l.startswith('p'):pid=int(l[1:])
  elif l.startswith('n'):listeners.append({'pid':pid,'role':'primary-xray' if pid==main[0]['pid'] else 'auxiliary-xray','endpoint':l[1:],'loopback':endpoint_loopback(l[1:])})
 primary=[l for l in listeners if l['role']=='primary-xray']
 if not primary or not any(l['endpoint']=='127.0.0.1:10808' for l in primary):raise ValueError('PRIMARY_LISTENER_BINDING_UNKNOWN')
 return {'processes':sorted(processes,key=lambda x:x['role']),'allXrayListeners':sorted(listeners,key=lambda x:(x['role'],x['endpoint'],x['pid'])),'identityDigest':digest(sorted(processes,key=lambda x:x['role']))}
def capture(label,contract):
 start=time.monotonic();at=datetime.datetime.now(datetime.timezone.utc).isoformat()
 try:
  runtime=ROOT/'binConfigs/config.json';gui=ROOT/'guiConfigs/guiNConfig.json';db=ROOT/'guiConfigs/guiNDB.db'
  rb=runtime.read_bytes();gb=gui.read_bytes();rx=parse(rb.decode('utf-8-sig'));gx=parse(gb.decode('utf-8-sig'))
  if not isinstance(rx,dict) or not isinstance(rx.get('inbounds'),list) or not isinstance(rx.get('outbounds'),list):raise ValueError('INVALID_RUNTIME_SCHEMA')
  files={'runtime':filemeta(runtime,rb),'gui':filemeta(gui,gb),'database':filemeta(db,db.read_bytes())}
  logical=database_snapshot(db);proc=process_state()
  main=next(p for p in proc['processes'] if p['role']=='primary-xray')
  if files['runtime']['mtimeNs']/1e9>=main['startEpochSeconds']+1:raise ValueError('RUNTIME_FILE_NEWER_THAN_CORE_START')
  if runtime.read_bytes()!=rb or gui.read_bytes()!=gb:raise ValueError('CONFIG_CHANGED_DURING_CAPTURE')
  immutable={p:sha(Path(p).read_bytes()) for p in contract['A']['files']}
  ports=[{'listen':i.get('listen'),'port':i.get('port'),'protocol':i.get('protocol'),'auth':i.get('settings',{}).get('auth'),'accountsPresent':bool(i.get('settings',{}).get('accounts')),'sniffingDigest':digest(i.get('sniffing'))} for i in rx['inbounds']]
  protected={'runtimeSemanticDigest':digest(rx),'guiSemanticDigest':digest(gx),'databaseSemanticDigest':logical['semanticDigest'],'allXrayListenerSemantics':sorted([{'role':l['role'],'endpoint':l['endpoint']} for l in proc['allXrayListeners']],key=lambda x:(x['role'],x['endpoint']))}
  public={'inbounds':ports,'lanExposure':any(not endpoint_loopback(str(i.get('listen','*'))+':'+str(i.get('port',0))) for i in rx['inbounds']),'routingMode':rx.get('routing',{}).get('domainStrategy'),'routingDigest':digest(rx.get('routing')),'outbounds':[{'tag':o.get('tag'),'protocol':o.get('protocol'),'allFieldsDigest':digest(o),'securityField':o.get('streamSettings',{}).get('security')} for o in rx['outbounds']],'dnsDigest':digest(rx.get('dns')),'policyDigest':digest(rx.get('policy')),'guiSelectionDigest':digest({k:gx.get(k) for k in ['IndexId','SubIndexId','RoutingBasicItem']}),'allJsonFieldsProtected':True}
  protected['publicSemanticsDigest']=digest(public)
  return {'sample':label,'startedAt':at,'completedAt':datetime.datetime.now(datetime.timezone.utc).isoformat(),'captureSeconds':time.monotonic()-start,'status':'CAPTURED','files':files,'logicalDatabase':logical,'protected':protected,'proxySemanticDigest':digest(protected),'publicSemantics':public,'processState':proc,'immutableProxyFiles':immutable,'classification':'REAL_READ_ONLY_CURRENT_STATE','privateContentArchived':False,'baselineEpochOnly':True}
 except (OSError,ValueError,sqlite3.Error,subprocess.TimeoutExpired) as e:
  return {'sample':label,'startedAt':at,'captureSeconds':time.monotonic()-start,'status':'CAPTURE_ERROR','errorType':type(e).__name__,'errorCode':str(e) if isinstance(e,ValueError) else 'READ_ONLY_CAPTURE_FAILED','privateContentArchived':False}
def validate_samples(samples,contract):
 failures=[];notes=[];cfg=contract['observation']
 if len(samples)!=cfg['samples'] or [x.get('sample') for x in samples]!=['T0','T1','T2','T3','T4']:failures.append('SAMPLE_SET')
 if any(x.get('status')!='CAPTURED' for x in samples):failures.append('CAPTURE_ERROR')
 if not samples or failures:return {'status':'FAILED','failures':failures,'benignDifferences':notes}
 base=samples[0];times=[datetime.datetime.fromisoformat(x['startedAt']) for x in samples];span=(times[-1]-times[0]).total_seconds()
 if not cfg['minimumSpanSeconds']<=span<=cfg['maximumSpanSeconds'] or any(a>=b for a,b in zip(times,times[1:])):failures.append('OBSERVATION_WINDOW')
 for s in samples:
  tag=s['sample']
  if s['proxySemanticDigest']!=digest(s['protected']) or s['protected']['publicSemanticsDigest']!=digest(s['publicSemantics']):failures.append(tag+':INVALID_SEMANTIC_BINDING')
  if s['processState']['identityDigest']!=digest(s['processState']['processes']):failures.append(tag+':INVALID_PROCESS_BINDING')
  if set(s['immutableProxyFiles'])!=set(contract['A']['files']) or set(s['files'])!={'runtime','gui','database'}:failures.append(tag+':INCOMPLETE_FILE_SET')
  if s['captureSeconds']>cfg['maximumCaptureSeconds']:failures.append(tag+':CAPTURE_DURATION')
  if s['protected']!=base['protected'] or s['proxySemanticDigest']!=base['proxySemanticDigest']:failures.append(tag+':SEMANTIC_DRIFT')
  if s['files']['runtime']['rawSha256']!=base['files']['runtime']['rawSha256']:failures.append(tag+':GENERATED_RAW_DRIFT_NOT_EXEMPT')
  if s['immutableProxyFiles']!=base['immutableProxyFiles']:failures.append(tag+':IMMUTABLE_PROXY_BYTES')
  if s['processState']['identityDigest']!=base['processState']['identityDigest']:failures.append(tag+':PRIMARY_PROCESS_IDENTITY_DRIFT')
  if any(not l['loopback'] for l in s['processState']['allXrayListeners']) or s['publicSemantics']['lanExposure']:failures.append(tag+':LAN_EXPOSURE')
  for name in ['gui','database']:
   if s['files'][name]['rawSha256']!=base['files'][name]['rawSha256'] and s['protected']==base['protected']:notes.append(tag+':'+name+':RAW_CHANGED_COMPLETE_LOGICAL_VALUES_IDENTICAL')
 return {'status':'FAILED' if failures else 'VERIFIED','failures':failures,'benignDifferences':notes,'spanSeconds':span,'sampleCount':len(samples),'observationLimit':'Two-minute current-state sampling, not proof across every future refresh interval'}
