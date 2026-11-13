import pathUtil from 'node:path';
const readers=new Set(['cat','head','tail','dd','cp','awk','sed']);
const openCalls=new Set(['open','openat','openat2','creat']);
const success=v=>v==='SUCCESS'||typeof v==='number'&&v>=0||typeof v==='string'&&/^\d+$/.test(v);
const criticalWrite=p=>['/etc/ld.so.preload','/etc/crontab','/etc/sudoers','/etc/ssh/sshd_config'].includes(p)||['/etc/cron.d/','/usr/bin/','/usr/sbin/','/bin/','/sbin/'].some(x=>p.startsWith(x));
export function runtimeWindow(events,workloads,start,end){
 const candidates=new Map(),warnings={};const seen=new Set();
 const warn=reason=>warnings[reason]=(warnings[reason]??0)+1;
 for(const e of events){
  if(!e?.rule)continue;const f=e.output_fields??{},at=Date.parse(e.time);
  if(!Number.isFinite(at)||at<start||at>=end){warn('historical-or-outside-window');continue;}
  const ns=f['k8s.ns.name'],pod=f['k8s.pod.name'],container=f['container.name'],cid=f['container.id'];
  if(ns==='devsecops-test'){warn('isolated-test-event-retained');continue;}
  if(ns!=='petclinic'){warn('outside-reviewed-business-scope');continue;}
  const w=workloads[`${ns}/${pod}/${container}`];const id=String(w?.containerId??'').replace(/^.*:\/\//,'');
  if(!w||w.node!=='devops'||!w.ready||!w.podUid||!/^[a-f0-9]{12,64}$/.test(cid??'')||!id.startsWith(cid)||!Number.isFinite(Date.parse(w.startedAt))||at<Date.parse(w.startedAt)){warn('current-workload-identity-unconfirmed');continue;}
  if(!success(f['evt.res'])){warn('failed-or-prevented-attempt');continue;}
  const rawPath=String(f['evt.arg.name']??'');const path=rawPath.startsWith('/')?pathUtil.posix.normalize(rawPath):rawPath,proc=String(f['proc.name']??'');let reason;
  if(e.rule==='Platform Runtime Sensitive Read'&&path==='/etc/shadow'&&readers.has(proc)&&openCalls.has(f['evt.type']))reason='successful-shadow-read-by-explicit-reader';
  if(e.rule==='Platform Runtime Sensitive Write'&&criticalWrite(path)&&openCalls.has(f['evt.type']))reason='successful-critical-system-path-write';
  if(!reason){warn('event-needs-review-not-proven-high-risk');continue;}
  const fingerprint=JSON.stringify([e.time,e.rule,cid,proc,path,f['evt.type']]);if(seen.has(fingerprint)){warn('duplicate-event');continue;}seen.add(fingerprint);
  const key=JSON.stringify([w.podUid,id,reason,proc,path]);
  const item=candidates.get(key)??{key,namespace:ns,pod,container,podUid:w.podUid,containerId:id,reason,process:proc,path,count:0};item.count++;candidates.set(key,item);
 }
 return {start:new Date(start).toISOString(),end:new Date(end).toISOString(),candidates:[...candidates.values()],warnings,scope:'Bounded local sensor window; raw commands and sensitive file contents are not included'};
}
export function persistentRuntime(first,second){
 if(Date.parse(second.start)<Date.parse(first.end))throw Error('Runtime policy requires disjoint windows');
 const blocking=first.candidates.filter(a=>a.count>=2).flatMap(a=>{const b=second.candidates.find(b=>b.key===a.key&&b.count>=2);return b?[{...a,firstCount:a.count,secondCount:b.count}]:[];});
 return {status:blocking.length?'failed':'success',blocking,first,second,criteria:'Same live Pod UID/container/process/path; >=2 unique successful events in each of two disjoint 15-second windows'};
}
