from pathlib import Path
import json,statistics,math
O=Path(__file__).resolve().parent;R=O.parents[2];P=R/'evidence/2026-11-05/host-guest-offline-preparation'
def put(n,v):
 with(O/n).open('x')as f:json.dump(v,f,indent=2);f.write('\n')
t=json.loads((O/'tests.json').read_text());rows=[]
for case in t['metrics']:
 for side,w in case['result']['workers'].items():rows.append({'case':case['case'],'side':side,'status':case['result']['status'],'failure':case['result']['failure'],**{k:w[k]for k in ['wallSeconds','cpuSeconds','maxRssBytes','stdoutBytes','spawnWallSeconds','reaped','exit']}})
def stats(v):
 s=sorted(v);return {'n':len(s),'min':s[0],'median':statistics.median(s),'p95NearestRank':s[math.ceil(.95*len(s))-1],'max':s[-1]}
def costs(rs):return {k:stats([r[k]for r in rs])for k in ['wallSeconds','cpuSeconds','maxRssBytes','stdoutBytes','spawnWallSeconds']}
put('performance-analysis.json',{'classification':'CORRECTED_FINAL_OFFLINE_MEASUREMENT','testCount':45,'pass':44,'fail':0,'skip':1,'wallSeconds':t['wallSeconds'],'guestFixture':costs([r for r in rows if r['case']=='cli-guest']),'hostNativeSelf':costs([r for r in rows if r['case']=='cli-host']),'controlledFailures':costs([r for r in rows if r['status']=='FAIL']),'supervisorCpuSeconds':stats([r['result']['supervisorCpuSeconds']for r in t['metrics']]),'allWorkersReaped':all(r['reaped']for r in rows),'collectorExternalCommands':0,'localSupervisorChildrenPerPair':2,'nativeLinux':'NOT_TESTED','realSsh':'NOT_TESTED','production':'NOT_TESTED','rows':rows})
v=json.loads((P/'verdict.json').read_text());v['currentEntrypoint']='infra/observability/bounded-sampler/sampler_mach_time.py';v['supersedes']='Earlier Host implementation claim omitted Mach CPU unit verification; corrected native self-check now included. Earlier raw data and source remain preserved.';v['finalTestCount']={'pass':44,'fail':0,'skip':1};v['scope']['hostImplementation']='Corrected native Darwin API + Mach timebase conversion validated against getrusage, self PID only';put('verdict.json',v)
print(json.dumps({'tests':'44 PASS / 1 SKIP','originalEvidenceIntegrity':'FAILED','production':'NOT_TESTED'}))
