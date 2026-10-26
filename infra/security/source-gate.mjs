import fs from 'node:fs';
import crypto from 'node:crypto';
import net from 'node:net';
import {spawnSync} from 'node:child_process';
const ns='devsecops-execution';
const out='.devsecops'; fs.mkdirSync(out,{recursive:true});
const tool=JSON.parse(fs.readFileSync('infra/security/tools-lock.json')).gitleaks;
function run(bin,args,input,expected=[0],timeout=30000){
 const r=spawnSync(bin,args,{input,encoding:typeof input==='object'?'buffer':'utf8',timeout,maxBuffer:128*1024*1024});
 if(r.error||!expected.includes(r.status))throw Error(`${bin} ${args[0]} failed (${r.status}): ${String(r.stderr).slice(-500)}`);
 return r;
}
const k=(args,input,expected=[0],timeout=30000)=>run('kubectl',['--request-timeout=20s',...args],input,expected,timeout);
const read=args=>JSON.parse(String(k([...args,'-o','json']).stdout));
const lease=read(['-n','data-infra','get','lease','platform-heavy']);
const holder=process.env.HEAVY_HOLDER||`jenkins-petclinic-${process.env.BUILD_NUMBER}`;
if(lease.spec.holderIdentity!==holder)throw Error('Existing outer heavy-task Lease must be owned; no nested lock acquired');
const source=String(run('git',['rev-parse','HEAD']).stdout).trim();
const name='source-'+String(process.env.BUILD_NUMBER||'manual')+'-'+crypto.randomBytes(3).toString('hex');
const labels={'petclinic.devops.local/owner':'platform-devsecops','petclinic.devops.local/run':name};
const pod={apiVersion:'v1',kind:'Pod',metadata:{name,namespace:ns,labels},spec:{automountServiceAccountToken:false,restartPolicy:'Never',activeDeadlineSeconds:600,nodeSelector:{'kubernetes.io/hostname':'devops','kubernetes.io/arch':'arm64'},securityContext:{runAsNonRoot:true,runAsUser:65532,runAsGroup:65532,fsGroup:65532,seccompProfile:{type:'RuntimeDefault'}},containers:[{name:'scanner',image:tool.image,command:['sh','-c','sleep 600'],resources:{requests:{cpu:'100m',memory:'256Mi','ephemeral-storage':'128Mi'},limits:{cpu:'1',memory:'512Mi','ephemeral-storage':'512Mi'}},securityContext:{allowPrivilegeEscalation:false,readOnlyRootFilesystem:true,capabilities:{drop:['ALL']}},volumeMounts:[{name:'work',mountPath:'/work'}]}],volumes:[{name:'work',emptyDir:{sizeLimit:'256Mi'}}]}};
const report={status:'failed',source,tool,startedAt:new Date().toISOString(),pod:name,namespace:ns,tests:[],cleanup:false};
let uid;
try{
 const created=JSON.parse(String(k(['create','-f','-','-o','json'],JSON.stringify(pod)).stdout));uid=created.metadata.uid;report.uid=uid;fs.writeFileSync(out+'/source-gate.json',JSON.stringify(report,null,2));
 k(['-n',ns,'wait','--for=condition=Ready','pod/'+name,'--timeout=180s'],undefined,[0],190000);
 const exec=(args,input,expected=[0])=>k(['-n',ns,'exec','-i',name,'--',...args],input,expected,90000);
 const reachable=()=>new Promise((resolve,reject)=>{const socket=net.connect({host:'10.0.0.3',port:6443,timeout:3000});socket.once('connect',()=>{socket.destroy();resolve(true);});socket.once('error',reject);socket.once('timeout',()=>{socket.destroy();reject(Error('Control-plane baseline unavailable'));});});
 await reachable();
 const help=exec(['nc','--help'],undefined,[0,1]);if(!String(help.stdout).concat(String(help.stderr)).includes('-z'))throw Error('Network probe binary lacks zero-I/O scan mode');
 const network=exec(['nc','-z','-v','-w','3','10.0.0.3','6443'],undefined,[0,1]);
 if(network.status!==1)throw Error('Scanner unexpectedly reached control-plane TCP endpoint');
 await reachable();
 exec(['sh','-c','test ! -e /var/run/secrets/kubernetes.io/serviceaccount/token']);
 if(String(exec(['id','-u']).stdout).trim()!=='65532')throw Error('Scanner effective UID differs');
 const rootWrite=exec(['touch','/devsecops-readonly-probe'],undefined,[0,1]);if(rootWrite.status!==1||!String(rootWrite.stderr).toLowerCase().includes('read-only file system'))throw Error('Actual read-only filesystem rejection required');
 report.isolation={controllerBaselineBeforeAndAfter:true,scannerControlPlaneTcpBlocked:true,networkDiagnostic:String(network.stderr).slice(0,500),serviceAccountTokenAbsent:true,effectiveUid:65532,readOnlyFilesystemVerified:true};
 report.actualImageID=read(['-n',ns,'get','pod',name]).status.containerStatuses[0].imageID;
 if(!report.actualImageID.includes(tool.image.split('@')[1]))throw Error('Observed scanner image differs from pinned ARM64 digest');
 exec(['mkdir','-p','/work/source','/work/fixture','/work/clean']);
 const archive=run('git',['archive','--format=tar','HEAD'],Buffer.alloc(0)).stdout;
 if(archive.length>128*1024*1024)throw Error('Source archive exceeds bounded scanner budget');
 exec(['tar','xf','-','-C','/work/source'],archive);report.archiveBytes=archive.length;
 const fake='ghp_'+crypto.randomBytes(18).toString('hex');
 exec(['sh','-c','cat > /work/fixture/test.txt'],`github_token = "${fake}"\n`);
 function scan(path,file){
  const result=exec(['gitleaks','dir',path,'--redact=100','--no-banner','--log-level','error','--report-format','json','--report-path',file],undefined,[0,1]);
  const findings=JSON.parse(String(exec(['cat',file]).stdout)||'[]');
  return {exit:result.status,findings:findings.map(x=>({rule:x.RuleID,file:x.File,line:x.StartLine,fingerprint:x.Fingerprint}))};
 }
 const positive=scan('/work/fixture','/work/positive.json');if(positive.exit!==1||!positive.findings.some(x=>x.rule==='github-pat'))throw Error('Synthetic credential was not blocked');
 report.tests.push({case:'synthetic-secret-blocked',...positive});
 const clean=scan('/work/clean','/work/clean.json');if(clean.exit!==0||clean.findings.length)throw Error('Clean fixture was not accepted');report.tests.push({case:'clean-fixture-accepted',...clean});
 report.sourceScan=scan('/work/source','/work/source.json');
 const reviewed=JSON.parse(fs.readFileSync('infra/security/reviewed-false-positives.json')).entries;
 const lines=new Map();report.sourceScan.verifiedFalsePositives=[];report.sourceScan.blockingFindings=[];
 for(const finding of report.sourceScan.findings){
  const relative=finding.file.replace(/^\/work\/source\//,'');
  if(relative===finding.file||relative.includes('..'))throw Error('Unexpected scanner file path');
  if(!lines.has(relative))lines.set(relative,String(exec(['cat','/work/source/'+relative]).stdout).split(/\r?\n/));
  const text=lines.get(relative)[finding.line-1];if(text===undefined)throw Error('Finding location missing in exact source');
  const hash=crypto.createHash('sha256').update(text).digest('hex');
  const accepted=reviewed.find(x=>x.path===relative&&x.rule===finding.rule&&x.line_sha256===hash);
  if(accepted)report.sourceScan.verifiedFalsePositives.push({...finding,line_sha256:hash,reason:accepted.reason});
  else report.sourceScan.blockingFindings.push(finding);
 }
 report.sourceScan.rawCount=report.sourceScan.findings.length;
 if(report.sourceScan.blockingFindings.length)throw Error(`Secret gate blocked ${report.sourceScan.blockingFindings.length} unaccepted findings; review redacted locations`);
 report.status='success';
}catch(e){report.error=e.message;throw e;}
finally{
 if(uid){
  const current=read(['-n',ns,'get','pod',name]);if(current.metadata.uid!==uid)throw Error('Refuse cleanup of replacement Pod');
  k(['-n',ns,'delete','pod',name,'--wait=true','--timeout=45s'],undefined,[0],55000);
  report.cleanup=String(k(['-n',ns,'get','pod',name,'--ignore-not-found','-o','name']).stdout).trim()==='';
 }
 report.finishedAt=new Date().toISOString();fs.writeFileSync(out+'/source-gate.json',JSON.stringify(report,null,2));
 if(uid&&!report.cleanup)throw Error('Scanner Pod cleanup incomplete');
}
console.log(JSON.stringify({status:report.status,source,pod:name,blockingFindings:report.sourceScan?.blockingFindings.length,rawFindings:report.sourceScan?.rawCount,cleanup:report.cleanup}));
