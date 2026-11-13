from pathlib import Path
import json,datetime
from history_tools import OLD,NEW,timestamp,ordered,sha
O=Path(__file__).resolve().parent;P=O.parent/'runtime-14-checkpoint-guard-review'
read=lambda n:json.loads((O/n).read_text())
save=lambda n,x:(O/n).write_text(json.dumps(x,ensure_ascii=False,indent=2)+'\n')
rows=read('capture-command-timing.json')['records'];before=next(x for x in rows if x['beforeArgument']);after=next(x for x in rows if x['afterArgument'])
iso=lambda ms:datetime.datetime.fromtimestamp(ms/1000,datetime.timezone.utc).isoformat()
old=json.load(open(P/'local-config-before.json'))['files']['proxyConfig'];new=json.load(open(P/'local-config-after.json'))['files']['proxyConfig']
events=[
 {'timestamp':'2026-11-03T03:03:48.737Z','event':'Earlier sealed partial runtime evidence processed by completed command','source':'trivy-infra-repair/local-baseline.json + capture-command-timing.json','precision':'Command completion bound, not exact earlier socket read','semanticScope':'127.0.0.1:10808 mixed/noauth; no outbound/routing identity'},
 {'timestamp':'2026-11-03T09:17:03.478948293Z','event':'Old config recorded mtime','source':'sealed local-config-before.json','precision':'Filesystem mtime; NOT write-event attribution'},
 {'timestamp':'2026-11-03T09:17:08.629300Z','event':'GUI WindowClosing','source':'application-log-window.json','precision':'Log timestamp, NOT process exit or file save'},
 {'timestamp':iso(before['startTimeMs']),'event':'Old-hash read command begins','source':'capture-command-timing.json','precision':'Earliest conservative drift-window bound; exact inner read not logged'},
 {'timestamp':iso(before['completedTimeMs']),'event':'Old-hash read command completes exit 0','source':'capture-command-timing.json + sealed local-config-before.json','precision':'Read lies within this command interval','sha256':OLD},
 {'timestamp':'2026-11-03T09:20:24.172875Z','event':'GUI AppKit activity changes termination eligibility','source':'historical-unified-log-recheck.json','precision':'Log event; NOT proof of config write'},
 {'timestamp':'2026-11-03T09:20:28Z','event':'Current main xray start second','source':'process-inventory.json','precision':'ps lstart has one-second precision; do not claim exact start instant'},
 {'timestamp':'2026-11-03T09:20:28.424101798Z','event':'New config recorded mtime','source':'sealed local-config-after.json','precision':'Filesystem mtime, NOT proven write time'},
 {'timestamp':iso(after['startTimeMs']),'event':'New-hash read command begins','source':'capture-command-timing.json','precision':'Exact inner read not logged'},
 {'timestamp':iso(after['completedTimeMs']),'event':'New-hash read command completes exit 0','source':'capture-command-timing.json + sealed local-config-after.json','precision':'Latest conservative drift-window bound','sha256':NEW},
 {'timestamp':read('observation-T0.json')['sampledAt'],'event':'Current read-only runtime sample','source':'observation-T0.json','precision':'Sample timestamp, not a stability or baseline-reset acceptance','sha256':read('observation-T0.json')['files'][0]['rawSha256']}
]
if (O/'additional-observed-drift.json').exists():
 extra=read('additional-observed-drift.json');latest=read('current-post-additional-drift.json')
 events.append({'timestamp':extra['observedAt'],'event':'Additional runtime config drift observed during this read-only review','source':'additional-observed-drift.json','precision':'Observation time, not attributed write time','sha256':extra['current']['sha256'],'bytes':extra['current']['bytes'],'cause':'UNKNOWN; agent writes/restarts zero'})
 events.append({'timestamp':latest['sampledAt'],'event':'Latest main-core and runtime semantics read-only capture','source':'current-post-additional-drift.json','precision':'Not a new baseline; does not explain original drift','sha256':latest['sha256']})
events.sort(key=lambda x:timestamp(x['timestamp']))
checks=[]
def check(name,ok):
 assert ok,name
 checks.append({'check':name,'result':'PASS'})
check('All explicit timestamps ordered and timezone-aware',ordered(events))
check('Old capture command interval valid',before['startTimeMs']<=before['completedTimeMs'])
check('New capture follows old capture',before['completedTimeMs']<after['startTimeMs']<=after['completedTimeMs'])
check('Both capture commands completed successfully',before['exitCode']==after['exitCode']==0)
check('Old/new digests bound to unchanged sealed metadata',old['sha256']==OLD and new['sha256']==NEW and OLD!=NEW)
check('Old mtime precedes old read interval',old['mtimeNs']/1e6<before['startTimeMs'])
check('New mtime lies in conservative observation window',before['startTimeMs']<new['mtimeNs']/1e6<after['completedTimeMs'])
check('Earlier T0 sample bound to original post-drift hash',read('observation-T0.json')['files'][0]['rawSha256']==NEW)
save('drift-timeline.json',{'events':events,'checks':checks,'observationWindow':{'start':iso(before['startTimeMs']),'end':iso(after['completedTimeMs']),'basis':'Successful old/new capture command intervals; NOT an exact file-write timestamp'},'fileWriteTimestampKnown':False,'writerKnown':False,'noMtimeOnlyAttribution':True})
base=O.parent/'trivy-infra-repair';sealed=json.load(open(base/'evidence-sha256.json'));facts=json.load(open(base/'local-baseline.json'));probes=json.load(open(base/'proxy-before.json'))
for n in ['local-baseline.json','proxy-before.json']:assert sha((base/n).read_bytes())==sealed['files'][n]
save('trusted-pre-drift-runtime-evidence.json',{'status':'FOUND','coverage':'PARTIAL_NOT_COMPLETE_SEMANTIC_EQUIVALENCE','sourcePaths':[str(base/'local-baseline.json'),str(base/'proxy-before.json')],'sealedHashes':{n:sealed['files'][n] for n in ['local-baseline.json','proxy-before.json']},'timestampBasis':'Earlier completed session commands; details in capture-command-timing.json. File mtime is corroboration only.','oldProcess':{'pid':facts['processes'][0]['pid'],'configSha256':facts['processes'][0]['configSha256'],'configPath':facts['processes'][0]['configPath'],'inbounds':facts['processes'][0]['inbounds']},'connectivity':[{'origin':p['origin'],'httpStatus':p.get('httpStatus'),'exit':p['exit'],'path':'LOOPBACK' if '127.0.0.1' in p['proxy'] else 'LAN'} for p in probes['probes']],'missing':['Immediate e3c322 old config bytes','Old complete routing rules/mode','Old outbound/server identity','Old TLS/security flags','Old 10812 listener baseline','DNS behavior'],'mustNotFillMissingWithCurrentValues':True})
print(json.dumps({'timelineConsistencyChecks':len(checks),'oldCaptureInterval':[iso(before['startTimeMs']),iso(before['completedTimeMs'])],'newCaptureInterval':[iso(after['startTimeMs']),iso(after['completedTimeMs'])],'historicalRuntimeEvidence':'FOUND_PARTIAL','writer':'WEAK'}))
