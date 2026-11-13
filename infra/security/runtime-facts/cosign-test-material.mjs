// Disposable validation trust only. No production key path is read.
import fs from 'node:fs';import {spawnSync} from 'node:child_process';import crypto from 'node:crypto';
const run=JSON.parse(fs.readFileSync('runtime-validation-run.json')).validationRunId,p='/tmp/runtime-three-'+run,tools=JSON.parse(fs.readFileSync('infra/security/scanner-tools.json'));
const action=process.argv[2],out='.devsecops/runtime-controlled/build-'+process.env.BUILD_NUMBER;fs.mkdirSync(out,{recursive:true});
function exec(bin,args,env={},input){const r=spawnSync(tools.root+'/'+bin,args,{env:{...process.env,...env,NODE_OPTIONS:''},input,encoding:'utf8',timeout:60000,maxBuffer:2*1024*1024});if(r.status!==0)throw Error('Disposable '+bin+' failed; output suppressed');return r.stdout;}
if(action==='create'){
 const t=p+'/cosign-test';if(fs.existsSync(t))throw Error('Unclean validation trust directory');fs.mkdirSync(t,{mode:0o700,recursive:true});
 try{
  const password=crypto.randomBytes(32).toString('hex');exec('cosign',['generate-key-pair','--output-key-prefix',t+'/cosign'],{COSIGN_PASSWORD:password});exec('age-keygen',['-o',t+'/age.key']);const recipient=exec('age-keygen',['-y',t+'/age.key']).trim();
  const bundle={schema:1,data:{privateKey:fs.readFileSync(t+'/cosign.key','utf8'),password}};
  const encrypted=exec('sops',['encrypt','--age',recipient,'--input-type','json','--output-type','json','--encrypted-regex','^(data)$','--filename-override',t+'/validation-bundle.json'],{},JSON.stringify(bundle));fs.writeFileSync(t+'/signing-bundle.enc.json',encrypted,{mode:0o600});
  fs.rmSync(t+'/cosign.key');const pub=fs.readFileSync(t+'/cosign.pub','utf8'),meta={validationRunId:run,classification:'DISPOSABLE_VALIDATION_TRUST',publicKey:pub,publicKeySha256:crypto.createHash('sha256').update(pub).digest('hex'),productionPrivateKeyReads:0,encryptedBundleSha256:crypto.createHash('sha256').update(encrypted).digest('hex')};fs.writeFileSync(t+'/public.json',JSON.stringify(meta));fs.writeFileSync(out+'/cosign-test-trust.json',JSON.stringify(meta));console.log(JSON.stringify({status:'TEST_TRUST_CREATED',publicKeySha256:meta.publicKeySha256,privateMaterialArchived:false}));
 }catch(e){fs.rmSync(t,{recursive:true,force:true});throw e;}
}else if(action==='delete'){
 fs.rmSync(p+'/cosign-test',{recursive:true,force:true});fs.writeFileSync(out+'/cosign-test-trust-cleanup.json',JSON.stringify({validationRunId:run,privateMaterialRemoved:!fs.existsSync(p+'/cosign-test'),productionPrivateKeyReads:0}));
}else throw Error('Explicit trust action required');
