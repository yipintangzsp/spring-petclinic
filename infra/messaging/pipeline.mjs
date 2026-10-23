import fs from 'node:fs';
import {createHash} from 'node:crypto';
import {execFileSync} from 'node:child_process';
const mode=process.argv[2], build=process.env.BUILD_NUMBER;
if(!/^\d+$/.test(build??''))throw Error('Explicit Jenkins build required');
const root=new URL('./',import.meta.url), read=name=>fs.readFileSync(new URL(name,root));
function kube(args,input,timeout=20000){return execFileSync('kubectl',['--request-timeout=12s',...args],{input:input===undefined?undefined:typeof input==='string'?input:JSON.stringify(input),encoding:'utf8',timeout,maxBuffer:4*1024*1024});}
const get=args=>JSON.parse(kube([...args,'-o','json']));
const lease=get(['-n','data-infra','get','lease','platform-heavy']);
if(lease.spec.holderIdentity!==`jenkins-petclinic-${build}`)throw Error('Must reuse the owned CI heavy Lease');
fs.mkdirSync('target/platform',{recursive:true});
const lock=JSON.parse(read('dependencies.json'));
const codeHash=createHash('sha256').update(read('worker.py')).digest('hex');
function artifact(name,data){fs.writeFileSync(`target/platform/messaging-${name}.json`,JSON.stringify(data,null,2));}
const sleep=ms=>new Promise(r=>setTimeout(r,ms));
if(mode==='test'){
 const dependencyName='clinic-mq-pika-0779a7c1';
 const old=kube(['-n','petclinic','get','cm',dependencyName,'--ignore-not-found','-o','json']);
 const cacheHit=Boolean(old.trim());
 let wheel;
 if(cacheHit){
  wheel=Buffer.from(JSON.parse(old).binaryData['pika.whl'],'base64');
 }else{
  const args=['-fLsS','--retry','1','--connect-timeout','8','--max-time','60'];
  if(process.env.PACKAGE_HTTPS_PROXY)args.push('--proxy',process.env.PACKAGE_HTTPS_PROXY);
  wheel=execFileSync('curl',[...args,lock.pika.url],{timeout:130000,maxBuffer:1048576});
 }
 if(createHash('sha256').update(wheel).digest('hex')!==lock.pika.sha256)throw Error('Pika dependency digest mismatch; preserve existing cache');
 if(!cacheHit)kube(['create','-f','-'],{apiVersion:'v1',kind:'ConfigMap',metadata:{name:dependencyName,namespace:'petclinic'},immutable:true,binaryData:{'pika.whl':wheel.toString('base64')}});
 const name=`clinic-mq-unit-${build}`;
 kube(['create','-f','-'],{apiVersion:'v1',kind:'ConfigMap',metadata:{name,namespace:'petclinic'},data:{'worker.py':read('worker.py').toString(),'test_worker.py':read('test_worker.py').toString()}});
 const job={apiVersion:'batch/v1',kind:'Job',metadata:{name,namespace:'petclinic'},spec:{backoffLimit:0,activeDeadlineSeconds:120,ttlSecondsAfterFinished:86400,template:{spec:{restartPolicy:'Never',automountServiceAccountToken:false,nodeSelector:{'kubernetes.io/hostname':'devops'},securityContext:{runAsUser:50000,runAsNonRoot:true,seccompProfile:{type:'RuntimeDefault'}},containers:[{name:'tests',image:lock.runtime,imagePullPolicy:'IfNotPresent',command:['python','-m','unittest','discover','-s','/opt/clinic-mq','-p','test_*.py'],env:[{name:'PYTHONDONTWRITEBYTECODE',value:'1'}],resources:{requests:{cpu:'50m',memory:'64Mi'},limits:{cpu:'200m',memory:'128Mi'}},securityContext:{allowPrivilegeEscalation:false,capabilities:{drop:['ALL']}},volumeMounts:[{name:'code',mountPath:'/opt/clinic-mq',readOnly:true},{name:'pika',mountPath:'/opt/clinic-deps',readOnly:true}]}],volumes:[{name:'code',configMap:{name}},{name:'pika',configMap:{name:dependencyName}}]}}}};
 let created=false;
 try{
  kube(['create','-f','-'],job);created=true;let result;
  for(let i=0;i<40;i++){
   result=get(['-n','petclinic','get','job',name]);
   if(result.status?.succeeded||result.status?.failed)break;
   await sleep(4000);
  }
  const log=kube(['-n','petclinic','logs',`job/${name}`]);
  artifact('python-tests',{build,worker_sha256:codeHash,status:result.status,log,pika_sha256:lock.pika.sha256,pika_cache_hit:cacheHit});
  if(result.status?.succeeded!==1)throw Error('Python message protocol tests failed');
 }finally{
  if(created)kube(['-n','petclinic','delete','job',name,'--wait=true','--timeout=40s'],undefined,50000);
  kube(['-n','petclinic','delete','cm',name]);
 }
}else if(mode==='deploy'){
 // Credential provisioning is intentionally outside Git; never print Secret contents.
 get(['-n','petclinic','get','secret','rabbitmq-client']);
 const role=Buffer.from(kube(['-n','petclinic','get','secret','petclinic-db','-o','jsonpath={.data.POSTGRES_USER}']).trim(),'base64').toString();
 if(!role||role.length>63||role.includes('\0'))throw Error('Invalid application DB role');
 const quoted='"'+role.replaceAll('"','""')+'"';
 const sql=read('schema.sql').toString()+`\nGRANT USAGE ON SCHEMA clinic_messaging TO ${quoted};\nGRANT SELECT,INSERT,UPDATE ON ALL TABLES IN SCHEMA clinic_messaging TO ${quoted};\n`;
 const before=kube(['-n','ns-data','exec','deploy/postgresql','--','psql','-U','postgres','-d','petclinic','-Atc',"SELECT to_regnamespace('clinic_messaging') IS NOT NULL"]);
 if(before.trim()==='t'){
  const previous=kube(['-n','ns-data','exec','deploy/postgresql','--','pg_dump','-U','postgres','-d','petclinic','--schema-only','--schema=clinic_messaging','--no-owner','--no-privileges']);
  fs.writeFileSync('target/platform/messaging-schema-before.sql',previous,{mode:0o600});
 }
 kube(['-n','ns-data','exec','-i','deploy/postgresql','--','psql','-U','postgres','-d','petclinic','--single-transaction','-v','ON_ERROR_STOP=1'],sql,50000);
 const triggerCheck=kube(['-n','ns-data','exec','-i','deploy/postgresql','--','psql','-X','-U','postgres','-d','petclinic','-v','ON_ERROR_STOP=1'],read('trigger-test.sql').toString(),30000);
 artifact('trigger-check',{passed:true,transaction_rolled_back:true,log:triggerCheck});
 // Add only this worker's independent Alloy chain; keep existing log routing byte-for-byte.
 const collector=get(['-n','monitoring','get','cm','alloy']);
 const oldLogs=collector.data['config.alloy'], fragment=read('worker-logs.alloy').toString();
 const marker=/\/\/ BEGIN clinic-message-worker owned log source v1[\s\S]*?\/\/ END clinic-message-worker owned log source v1\n?/g;
 if([...oldLogs.matchAll(marker)].length>1)throw Error('Ambiguous worker log source; preserve collector');
 const nextLogs=oldLogs.match(marker)?oldLogs.replace(marker,fragment):oldLogs+'\n'+fragment;
 if(!oldLogs.includes('discovery.kubernetes "pods"')||!oldLogs.includes('loki.write "default"'))throw Error('Existing collector contract changed');
 const validation=kube(['-n','monitoring','exec','-i','ds/alloy','-c','alloy','--','/bin/sh','-c',`set -eu; f=$(mktemp /tmp/clinic-mq-config.XXXXXX); trap 'rm -f "$f"' EXIT; cat >"$f"; /bin/alloy validate "$f"`],nextLogs,30000);
 if(nextLogs!==oldLogs){
  fs.writeFileSync('target/platform/alloy-before-messaging.txt',oldLogs,{mode:0o600});
  kube(['-n','monitoring','patch','cm','alloy','--type=json','-p',JSON.stringify([
   {op:'test',path:'/metadata/resourceVersion',value:collector.metadata.resourceVersion},
   {op:'replace',path:'/data/config.alloy',value:nextLogs}
  ])]);
 }
 artifact('log-source',{changed:nextLogs!==oldLogs,source_sha256:createHash('sha256').update(fragment).digest('hex'),preserved_existing_chains:true,validation});
 const revision=fs.readFileSync('.git-sha','utf8').trim();if(!/^[a-f0-9]{40}$/.test(revision))throw Error('Validated source SHA missing');
 const app=JSON.parse(fs.readFileSync('infra/devops-lab/applications/platform-messaging.json','utf8'));app.spec.source.targetRevision=revision;
 kube(['apply','-f','-'],app);
 let state;
 for(let i=0;i<80;i++){
  state=get(['-n','argocd','get','app','platform-messaging']);
  if(state.status?.sync?.revision===revision&&state.status.sync.status==='Synced'&&state.status.health?.status==='Healthy')break;
  await sleep(5000);
 }
 artifact('deployment',{source:revision,worker_sha256:codeHash,sync:state.status?.sync,health:state.status?.health,migration:'additive',business_rows_rewritten:false});
 if(state.status?.sync?.revision!==revision||state.status.sync.status!=='Synced'||state.status.health?.status!=='Healthy'){
  try{console.error(kube(['-n','petclinic','logs','deploy/clinic-message-worker','--tail=40']));}catch{}
  throw Error('Message worker did not converge to the validated revision');
 }
}else if(mode==='release'){
 const event={release:process.env.IMAGE_TAG,build:Number(build),source_commit:fs.readFileSync('.git-sha','utf8').trim()};
 const result=JSON.parse(kube(['-n','petclinic','exec','-i','deploy/clinic-message-worker','--','python','/opt/clinic-mq/worker.py','publish-release'],event,100000));
 if(result.status!=='success'||result.worker_sha256!==codeHash)throw Error('Release was not consumed by the expected worker');
 artifact('release',result);console.log(JSON.stringify(result));
}else throw Error('Unknown message pipeline operation');
