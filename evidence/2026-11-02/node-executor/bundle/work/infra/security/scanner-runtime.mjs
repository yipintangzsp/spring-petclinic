import fs from 'node:fs';
import crypto from 'node:crypto';
import net from 'node:net';
import os from 'node:os';
import {spawn,spawnSync} from 'node:child_process';

export const toolchain=JSON.parse(fs.readFileSync('infra/security/scanner-tools.json'));
if(crypto.createHash('sha256').update(fs.readFileSync('infra/security/scanner-tools.json')).digest('hex')!==JSON.parse(fs.readFileSync('infra/security/tools-lock.json')).supplyChain.scanner_manifest_sha256)throw Error('Locked scanner tool manifest mismatch');
export function run(bin,args,input,allowed=[0],timeout=30000){
 const r=spawnSync(bin,args,{input,encoding:Buffer.isBuffer(input)?'buffer':'utf8',timeout,maxBuffer:16*1024*1024});
 if(r.error||!allowed.includes(r.status))throw Error(`${bin} failed (${r.status}): ${String(r.stderr).slice(-1200)}`);
 return r;
}
export const kube=(args,input,allowed=[0],timeout=30000)=>run('kubectl',['--request-timeout=20s',...args],input,allowed,timeout);
export const read=args=>JSON.parse(kube([...args,'-o','json']).stdout);
export function requireLease(){
 const x=read(['-n','data-infra','get','lease','platform-heavy']);
 if(x.spec.holderIdentity!==(process.env.HEAVY_HOLDER||`jenkins-petclinic-${process.env.BUILD_NUMBER}`))throw Error('Existing outer heavy Lease required; nested acquisition forbidden');
}
export function verifyTools(prefix){
 for(const entry of toolchain.files.filter(x=>prefix.some(p=>x.path===p||x.path.startsWith(p+'/')))){
  const file=toolchain.root+'/'+entry.path;
  if(entry.symlink){if(fs.readlinkSync(file)!==entry.symlink)throw Error('Tool symlink changed: '+entry.path);}
  else if(crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex')!==entry.sha256)throw Error('Tool changed: '+entry.path);
 }
}
export async function transfer(args,dest){
 const source=spawn('tar',args,{stdio:['ignore','pipe','pipe']});
 const sink=spawn('kubectl',['--request-timeout=120s',...dest],{stdio:['pipe','ignore','pipe']});
 source.stdout.pipe(sink.stdin);sink.stdin.on('error',()=>{});
 const controller=setTimeout(()=>{source.kill();sink.kill();},150000);
 try{
  const wait=p=>new Promise((resolve,reject)=>{p.once('error',reject);p.once('close',code=>code===0?resolve():reject(Error('Bounded archive transfer failed')));});
  await Promise.all([wait(source),wait(sink)]);
 }finally{clearTimeout(controller);if(source.exitCode===null)source.kill();if(sink.exitCode===null)sink.kill();}
}
export async function withScanner(kind,payload,action){
 requireLease();verifyTools(payload);
 const ns='devsecops-execution',name=kind+'-'+String(process.env.BUILD_NUMBER||'manual')+'-'+crypto.randomBytes(3).toString('hex');
 const pod={apiVersion:'v1',kind:'Pod',metadata:{name,namespace:ns,labels:{'petclinic.devops.local/owner':'platform-devsecops','petclinic.devops.local/scan-kind':kind}},spec:{automountServiceAccountToken:false,restartPolicy:'Never',activeDeadlineSeconds:600,nodeSelector:{'kubernetes.io/hostname':'devops','kubernetes.io/arch':'arm64'},securityContext:{runAsNonRoot:true,runAsUser:10001,runAsGroup:10001,fsGroup:10001,seccompProfile:{type:'RuntimeDefault'}},containers:[{name:'scanner',image:toolchain.baseImage,command:['sh','-c','sleep 600'],resources:{requests:{cpu:'100m',memory:'256Mi','ephemeral-storage':'512Mi'},limits:{cpu:'1',memory:'768Mi','ephemeral-storage':'1536Mi'}},securityContext:{allowPrivilegeEscalation:false,readOnlyRootFilesystem:true,capabilities:{drop:['ALL']}},volumeMounts:[{name:'work',mountPath:'/work'},{name:'tmp',mountPath:'/tmp'}]}],volumes:[{name:'work',emptyDir:{sizeLimit:'1024Mi'}},{name:'tmp',emptyDir:{sizeLimit:'128Mi'}}]}};
 const report={status:'failed',source:fs.readFileSync('.git-sha','utf8').trim(),pod:name,namespace:ns,startedAt:new Date().toISOString(),cleanup:false};let uid,canary;
 try{
  uid=JSON.parse(kube(['create','-f','-','-o','json'],JSON.stringify(pod)).stdout).metadata.uid;report.uid=uid;
  fs.mkdirSync('.devsecops',{recursive:true});fs.writeFileSync('.devsecops/'+kind+'-gate.json',JSON.stringify(report,null,2));
  kube(['-n',ns,'wait','--for=condition=Ready','pod/'+name,'--timeout=180s'],undefined,[0],190000);
  const exec=(args,input,allowed=[0],timeout=90000)=>kube(['-n',ns,'exec','-i',name,'--',...args],input,allowed,timeout);
  exec(['sh','-c','test "$(id -u)" = 10001; test ! -e /var/run/secrets/kubernetes.io/serviceaccount/token; ! touch /readonly-probe 2>/dev/null']);
  const ip=os.networkInterfaces().eth0?.find(x=>x.family==='IPv4')?.address;
  if(!/^10\.42\.0\.\d+$/.test(ip??''))throw Error('Measured Jenkins Pod IP required');
  canary=net.createServer(s=>{s.on('error',()=>{});s.end('policy-canary');});
  await new Promise((resolve,reject)=>{canary.once('error',reject);canary.listen(0,ip,resolve);});
  const port=canary.address().port;
  const baseline=()=>new Promise((resolve,reject)=>{const s=net.connect({host:ip,port,timeout:2000});s.once('connect',()=>{s.destroy();resolve();});s.once('error',reject);s.once('timeout',()=>{s.destroy();reject(Error('Canary baseline unavailable'));});});
  let denied=0;
  for(let i=0;i<15&&denied<2;i++){
   await baseline();const result=exec(['timeout','2','bash','-c',`echo probe >/dev/tcp/${ip}/${port}`],undefined,[0,1,124]);await baseline();
   denied=result.status===0?0:denied+1;if(denied<2)await new Promise(r=>setTimeout(r,1000));
  }
  if(denied<2)throw Error('Network isolation not proven; tool/source transfer refused');
  report.isolation={canaryDenied:true,canaryBaselineBeforeAndAfter:true,tokenAbsent:true,uid:10001,readOnlyRoot:true,nodeFirewallClaim:false};
  exec(['mkdir','-p','/work/tools']);
  await transfer(['cf','-','-C',toolchain.root,...payload],['-n',ns,'exec','-i',name,'--','tar','xf','-','-C','/work/tools']);
  await action({exec,report,pod:name,namespace:ns});
  report.status='success';report.memoryPeakBytes=String(exec(['cat','/sys/fs/cgroup/memory.peak'],undefined,[0,1]).stdout).trim();
 }catch(e){report.error=e.message;throw e;}
 finally{
  if(canary)canary.close();
  if(uid){const now=read(['-n',ns,'get','pod',name]);if(now.metadata.uid!==uid)throw Error('Replacement scanner preserved');
   const options={apiVersion:'v1',kind:'DeleteOptions',preconditions:{uid}};
   kube(['delete','--raw',`/api/v1/namespaces/${ns}/pods/${name}`,'-f','-'],JSON.stringify(options));
   for(let i=0;i<45;i++){if(!String(kube(['-n',ns,'get','pod',name,'--ignore-not-found','-o','name']).stdout).trim()){report.cleanup=true;break;}await new Promise(r=>setTimeout(r,1000));}
  }
  report.finishedAt=new Date().toISOString();fs.mkdirSync('.devsecops',{recursive:true});fs.writeFileSync('.devsecops/'+kind+'-gate.json',JSON.stringify(report,null,2));
  if(uid&&!report.cleanup)throw Error('Scanner cleanup incomplete');
 }
 return report;
}
