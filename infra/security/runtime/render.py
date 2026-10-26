"""Offline, pinned chart rendering on the admin workstation: python3 render.py /path/falco-9.2.1.tgz. Requires existing Helm/PyYAML; no downloads."""
from pathlib import Path
import sys,json,hashlib,subprocess,yaml
P=Path(__file__).resolve().parent;chart=Path(sys.argv[1]);lock=json.loads((P/'lock.json').read_text())
assert hashlib.sha256(chart.read_bytes()).hexdigest()==lock['chartSha256'],'Pinned official chart required'
rules=(P/'platform-rules.yaml').read_text();digest=hashlib.sha256(rules.encode()).hexdigest();epoch=digest[:12]
values=yaml.safe_load((P/'values.yaml').read_text());values['customRules']={'platform-rules.yaml':rules};values.setdefault('podLabels',{})['petclinic.devops.local/runtime-ruleset']=epoch;(P/'values.yaml').write_text(yaml.safe_dump(values,sort_keys=False))
render=subprocess.check_output(['/opt/homebrew/bin/helm','template','platform-falco',str(chart),'--namespace','devsecops-system','-f',str(P/'values.yaml')],text=True)
docs=[x for x in yaml.safe_load_all(render) if x];assert len(docs)==6
for d in docs:
 d['metadata'].setdefault('labels',{}).update({'petclinic.devops.local/owner':'platform-runtime-security','app.kubernetes.io/instance':'platform-devsecops'})
 if d['kind']=='ServiceMonitor':d['spec']['selector']['matchLabels']['app.kubernetes.io/instance']='platform-devsecops'
 if d['kind']=='DaemonSet':
  s=d['spec']['template']['spec'];s['hostPID']=True;s['automountServiceAccountToken']=False;c=s['containers'][0];c['image']='127.0.0.1:30050/platform-security/falco@'+lock['arm64ManifestDigest'];remove={'boot-fs','lib-modules','usr-fs','etc-fs'};s['volumes']=[v for v in s['volumes'] if v['name'] not in remove];c['volumeMounts']=[v for v in c['volumeMounts'] if v['name'] not in remove]
  for m in c['volumeMounts']:
   if m['name']=='container-engine-socket-0':m['readOnly']=True
  s.pop('initContainers',None)
(P/'falco.json').write_text(json.dumps({'apiVersion':'v1','kind':'List','items':docs},indent=2)+'\n');lock.update({'manifestSha256':hashlib.sha256((P/'falco.json').read_bytes()).hexdigest(),'rulesetSha256':digest,'rulesetLabel':epoch});(P/'lock.json').write_text(json.dumps(lock,indent=2)+'\n')
D=P.parent/'dashboard.json';cm=json.loads(D.read_text());key=next(iter(cm['data']));dash=json.loads(cm['data'][key]);import re
for p in dash['panels']:
 if 21<=p['id']<=27:
  p['description']='Current reviewed ruleset '+epoch+'; historical rulesets remain queryable in Loki. Controlled tests and expected activity are not automatically attacks.'
  for t in p['targets']:
   t['expr']=re.sub(r'\{app="platform-falco"(?:,runtime_ruleset="[^" ]+")?\}', '{app="platform-falco",runtime_ruleset="'+epoch+'"}',t['expr'])
   t['expr']=t['expr'].replace('| rule!=""','| source="syscall" | rule=~"Platform Runtime .*"')
 if 23<=p['id']<=26:p['options']['reduceOptions'].update({'values':True,'limit':50});p['options']['namePlacement']='left'
 if p['id']==28:
  p['gridPos']['y']=62;p['options']['content']=p['options']['content'].split('\n\nBusiness panels select reviewed ruleset ')[0]+'\n\nBusiness panels select reviewed ruleset '+epoch+'. Earlier versions remain in {app="platform-falco"}. The separate sensor diagnostics panel includes historical internal drop reports across all versions; no reports is not proof of lossless capture.'
if not any(p['id']==29 for p in dash['panels']):
 import copy
 p=copy.deepcopy(next(p for p in dash['panels'] if p['id']==27));p.update({'id':29,'title':'Falco sensor diagnostics — internal drop reports (all versions)','description':'Historical per-process startup drop reports remain visible. Empty window means no received reports, not a lossless-capture guarantee. Inspect Prometheus counters and process lifecycle separately.','gridPos':{'x':0,'y':54,'w':24,'h':8}});p['targets'][0]['expr']='{app="platform-falco"} | json | __error__="" | rule="Falco internal: syscall event drop"';p['targets'][0]['queryType']='range';dash['panels'].append(p)
cm['data'][key]=json.dumps(dash,ensure_ascii=False,indent=2);D.write_text(json.dumps(cm,ensure_ascii=False,indent=2)+'\n');print(json.dumps({'resources':len(docs),'ruleset':epoch,'chart':lock['chartVersion']}))
