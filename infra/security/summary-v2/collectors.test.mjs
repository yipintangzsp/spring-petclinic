// T08a / C1+C2: runtime collectors produce raw facts that the existing
// frozen-replay adapters evaluate to a verdict (receipt.error === null),
// and the emit path hands receipts off through the claim protocol.
import assert from 'node:assert';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {binding} from './fixture-harness.mjs';
import {createSourceOwner} from './owner.mjs';
import {validateResult} from './results.mjs';
import {runBinding} from './collectors/context.mjs';
import {emitReceipt} from './collectors/emit.mjs';
import {createSopsCollector} from './collectors/sops.mjs';
import {createFalcoCollector,falcoSourceId} from './collectors/falco.mjs';
import {createKubescapeCollector} from './collectors/kubescape.mjs';
import {createCosignCollector} from './collectors/cosign.mjs';
import {createDojoCollector} from './collectors/defectdojo.mjs';
import {createRbacPartCollector,createAdmissionPartCollector,writeKyvernoPart,runKey} from './collectors/kyverno.mjs';

process.env.BUILD_NUMBER = '7';
const owner = createSourceOwner(binding);
const ev = (sourceId,facts) => owner.evaluateOnce(sourceId,facts);
const verdict = r => { assert.equal(r.error,null,`${r.sourceId}: ${r.error?.message}`); return r.result.status; };

// --- emit path: binding resolution + claim handoff in a run directory ---
{
  const root = fs.mkdtempSync(path.join(os.tmpdir(),'t08a-emit-'));
  fs.mkdirSync(root+'/.devsecops',{recursive:true});
  fs.writeFileSync(root+'/.git-sha','a'.repeat(40));
  fs.writeFileSync(root+'/.devsecops/trivy-audit.json',JSON.stringify(
    {auditTargetImage:'registry.invalid/x@sha256:'+'b'.repeat(64),targetScope:'candidate'}));
  const out = await emitReceipt('sops',{component:'sops',status:'error',raw:{}},{root});
  assert.equal(out.emitted,true,out.reason);
  validateResult(out.receipt,runBinding(root));
}

// --- sops: full success-path observations through the collector ---
{
  const c = createSopsCollector();
  c.prerequisites({manifest:true,lease:true,tools:true,credentialPresent:true});
  c.sourceRead(true); c.begin(true,4);
  const names = [['petclinic','petclinic-db'],['petclinic','rabbitmq-client'],
    ['petclinic','petclinic-harbor-pull'],['devsecops-system','kyverno-registry-pull']];
  for (const [ns,n] of names) {
    const secret = {kind:'Secret',apiVersion:'v1',metadata:{name:n,namespace:ns,uid:'uid-'+n},
      type:'Opaque',data:{password:'eA=='}};
    const t = c.target(ns,n,{status:0,stdout:JSON.stringify(secret),stderr:''});
    t.readSucceeded = true; t.actual = structuredClone(secret);
    t.afterReadSucceeded = true; t.after = structuredClone(secret);
  }
  c.rbac({knownGet:'yes',knownRegistryGet:'yes',registryForeignGet:'no',registryList:'no',
    registryCreate:'no',foreignGet:'no',createSecret:'no',listSecrets:'no',otherNamespace:'no'});
  c.verifierRbac({ownCredentialGet:'yes',oldCrossGet:'no',businessDatabaseGet:'no',businessSecretList:'no'});
  c.reportWrite(true);
  const r = await ev('sops',{component:'sops',status:'success',raw:c.raw});
  assert.equal(verdict(r),'PASS');
}

// --- falco: baseline then final over one synthetic sensor identity ---
{
  const startedAt = new Date(Date.now()-900000).toISOString();
  const pod = {metadata:{name:'falco-x',uid:'uid-1',labels:{'petclinic.devops.local/runtime-ruleset':'rules-v1'}},
    spec:{nodeName:'devops',containers:[{name:'falco',image:'falco@sha256:'+'e'.repeat(64)}]},
    status:{phase:'Running',podIP:'10.42.0.9',containerStatuses:[{name:'falco',
      containerID:'containerd://cid1',restartCount:0,ready:true,state:{running:{startedAt}}}]}};
  const lock = {rulesetLabel:'rules-v1',manifestSha256:'f'.repeat(64),arm64ManifestDigest:'sha256:'+'e'.repeat(64)};
  const proof = {kind:'falco-isolated-sensor-proof',rulesetLabel:'rules-v1',cleanup:{removed:true},
    cases:[{case:'synthetic',status:'pass'}]};
  const fill = c => {
    c.leaseOk();
    c.file('proof',JSON.stringify(proof)); c.file('lock',JSON.stringify(lock));
    c.file('manifestHash','f'.repeat(64)); c.file('source','a'.repeat(40));
    c.cmd('ds',{status:0,stdout:JSON.stringify({status:{desiredNumberScheduled:1,numberReady:1}}),stderr:''});
    c.cmd('sensorPods',{status:0,stdout:JSON.stringify({items:[pod]}),stderr:''});
    c.cmd('node',{status:0,stdout:JSON.stringify({status:{nodeInfo:{bootID:'boot-1'}}}),stderr:''});
    c.cmd('diagnosticLog',{status:0,stdout:'',stderr:''});
    c.sample(Date.now(),{status:0,stdout:'',stderr:''},{status:0,stdout:JSON.stringify({items:[]}),stderr:''});
    c.health(200); c.flag('mkdirSucceeded',true); c.flag('reportWriteSucceeded',true);
  };
  const cb = createFalcoCollector('baseline'); fill(cb); cb.flag('baselineExists',false);
  cb.flag('baselineWriteSucceeded',true);
  const rb = await ev('falco-baseline',{component:'falco-baseline',status:'success',raw:cb.raw});
  assert.equal(verdict(rb),'PASS');

  const baselineObj = {podUid:'uid-1',nodeBootId:'boot-1',containerId:'containerd://cid1',
    runningSince:startedAt,image:'falco@sha256:'+'e'.repeat(64),restarts:0,
    source:'a'.repeat(40),build:'7',capturedAt:new Date(Date.now()-60000).toISOString()};
  const cf = createFalcoCollector('check'); fill(cf); cf.flag('baselineExists',true);
  cf.file('baseline',JSON.stringify(baselineObj));
  const rf = await ev('falco-final',{component:'falco-final',status:'success',raw:cf.raw});
  assert.equal(verdict(rf),'PASS');
  assert.equal(falcoSourceId('check'),'falco-final');
}

// --- kubescape: lock, probes and four scan entries through the collector ---
{
  const c = createKubescapeCollector();
  const lock = {version:'v3',path:'/tmp/ks-bin',sha256:'a'.repeat(64),
    artifactRoot:'/tmp/ks-art',artifacts:{'controls.json':'b'.repeat(64)}};
  c.lock(lock,'holder-1');
  for (const f of ['lockReadSucceeded','outputDirSucceeded','sourceReadSucceeded',
    'tempCreateSucceeded','tempChmodSucceeded','configWriteSucceeded','cleanupSucceeded',
    'finalReportWriteSucceeded']) c.flag(f,true);
  c.hash('/tmp/ks-bin','a'.repeat(64)); c.hash('/tmp/ks-art/controls.json','b'.repeat(64));
  c.cmd('lease',{status:0,stdout:JSON.stringify({spec:{holderIdentity:'holder-1'}}),stderr:''});
  c.cmd('server',{status:0,stdout:'https://127.0.0.1:6443',stderr:''});
  c.cmd('ca',{status:0,stdout:JSON.stringify({data:{'ca.crt':'-----BEGIN CERTIFICATE-----\neA==\n-----END CERTIFICATE-----'}}),stderr:''});
  c.cmd('token',{status:0,stdout:'token-value',stderr:''});
  c.cmd('secretReadCheck',{status:1,stdout:'no',stderr:''});
  c.cmd('businessWriteCheck',{status:1,stdout:'no',stderr:''});
  const report = JSON.stringify({summaryDetails:{score:100},results:[],resources:[]});
  for (let i = 0; i < 4; i++) c.scan(i,c.scanEntry({status:0,stdout:'',stderr:''},true,report,
    crypto.createHash('sha256').update(report).digest('hex')));
  const r = await ev('kubescape',{component:'kubescape',status:'success',raw:c.raw});
  verdict(r); // adapter completes; verdict depends on native report content
}

// --- cosign: bootstrap stage through the collector ---
{
  process.env.HARBOR_USER = 'robot'; process.env.SIGNING_AGE_FILE = '/tmp/age';
  process.env.HARBOR_PASS = 'secret';
  const c = createCosignCollector('bootstrap'); c.environment();
  const manifest = JSON.stringify({tools:{cosign:{path:'/tmp/cosign-bin',sha256:'c'.repeat(64)}}});
  c.runtimeManifest(manifest,crypto.createHash('sha256').update(manifest).digest('hex'));
  c.runtimeLease({status:0,stdout:JSON.stringify({spec:{holderIdentity:'holder-1'}}),stderr:''});
  c.tool('/tmp/cosign-bin',{sha256:'c'.repeat(64)});
  c.file('.git-sha','a'.repeat(40)); c.file('infra/security/cosign.pub','PUBKEY');
  c.cmd('sops',['decrypt'],{status:0,stdout:JSON.stringify({schema:1,data:{privateKey:'k',password:'p'}}),stderr:''});
  c.cmd('cosign',['public-key'],{status:0,stdout:'PUBKEY',stderr:''});
  const img1 = 'core.harbor.domain/petclinic/petclinic@sha256:'+'1'.repeat(64);
  const img2 = 'core.harbor.domain/petclinic/petclinic@sha256:a8c03e462e44ec81d4b685dd88618ab5fd0b3847411ddcd067d8a92b2071e268';
  c.currentImage({status:0,stdout:JSON.stringify({spec:{template:{spec:{containers:[{image:img1}]}}}}),stderr:''});
  for (const img of [img1,img2]) {
    c.cmd('cosign',['sign'],{status:0,stdout:'',stderr:''});
    c.cmd('cosign',['verify'],{status:0,
      stdout:JSON.stringify([{critical:{image:{'docker-manifest-digest':img.split('@')[1]}}}]),stderr:''});
  }
  for (const k of ['output-mkdir','temp-create','temp-chmod','key-write','docker-mkdir',
    'docker-write','temp-remove','signing-report-write']) c.io(k,true);
  c.io('temp-exists',false);
  const r = await ev('cosign',{component:'cosign',status:'success',raw:c.raw});
  verdict(r);
}

// --- defectdojo: files + API log through the collector, frozen replay ---
{
  process.env.DEFECTDOJO_TOKEN = 't'; process.env.SONAR_TOKEN = 's';
  const dir = fs.mkdtempSync(path.join(os.tmpdir(),'t08a-dojo-'));
  const prev = process.cwd(); process.chdir(dir);
  try {
    fs.mkdirSync('.devsecops',{recursive:true});
    fs.mkdirSync('infra/security/governance',{recursive:true});
    fs.writeFileSync('.git-sha','a'.repeat(40));
    const target = {product:1,engagement:2,baseUrl:'http://dojo.invalid'};
    fs.writeFileSync('infra/security/governance/dojo-target.json',JSON.stringify(target));
    fs.writeFileSync('.devsecops/gitleaks-native.json','{}');
    fs.writeFileSync('.devsecops/semgrep-native.json','{}');
    fs.writeFileSync('.devsecops/zap-business-report.xml','<xml/>');
    const ksScans = [0,1,2,3].map(i => ({scope:i < 2 ? 'cluster' : 'yaml',
      framework:i % 2 ? 'cis-v1.12.0' : 'nsa',reportFile:`.devsecops/kubescape/s${i}.json`}));
    fs.mkdirSync('.devsecops/kubescape',{recursive:true});
    for (const s of ksScans) fs.writeFileSync(s.reportFile,'{}');
    fs.writeFileSync('.devsecops/kubescape-gate.json',JSON.stringify(
      {status:'success',source:'a'.repeat(40),scans:ksScans}));
    fs.writeFileSync('.devsecops/trivy-audit.json',JSON.stringify({status:'success',
      targetScope:'candidate',runtimeImage:'r',auditTargetImage:'a',
      scans:[{digest:'sha256:'+'d'.repeat(64),scan:{scan_status:'Success'},raw:{}}]}));
    fs.writeFileSync('.devsecops/source-gate.json',JSON.stringify({status:'success'}));
    const c = createDojoCollector();
    c.build(); c.credentials(); c.target(target);
    c.recordFiles(['.git-sha','infra/security/governance/dojo-target.json',
      '.devsecops/gitleaks-native.json','.devsecops/semgrep-native.json',
      '.devsecops/zap-business-report.xml','.devsecops/trivy-audit.json',
      '.devsecops/kubescape-gate.json','.devsecops/source-gate.json',
      ...ksScans.map(s => s.reportFile)]);
    c.sonar({paging:{total:0},issues:[]});
    const stub = async url => { const body = String(url).includes('/tests/')
      ? {results:[],next:null} : {results:[],next:null};
      return {status:200,ok:true,clone(){ return {json:async () => body}; },json:async () => body}; };
    const fetchImpl = c.wrapFetch(stub);
    await fetchImpl('http://dojo.invalid/api/v2/tests/?limit=100&engagement=2');
    await fetchImpl('http://dojo.invalid/api/v2/findings/?limit=200&test__engagement__product=1');
    c.finish();
    const r = await ev('defectdojo',{component:'defectdojo',status:'success',raw:c.raw});
    assert.equal(verdict(r),'PASS');
  } finally { process.chdir(prev); }
}

// --- kyverno: two parts merge into one receipt through completeKyverno ---
{
  const root = fs.mkdtempSync(path.join(os.tmpdir(),'t08a-kyverno-'));
  fs.mkdirSync(root+'/.devsecops',{recursive:true});
  fs.writeFileSync(root+'/.git-sha','a'.repeat(40));
  fs.writeFileSync(root+'/.devsecops/trivy-audit.json',JSON.stringify(
    {auditTargetImage:'registry.invalid/x@sha256:'+'b'.repeat(64),targetScope:'candidate'}));
  const run = runKey(root);
  const rbac = createRbacPartCollector();
  rbac.cmd({status:0,stdout:'{}',stderr:''}); rbac.reportWrite(true);
  writeKyvernoPart(root,'rbac',run,rbac.observations,undefined,'success');
  const adm = createAdmissionPartCollector();
  adm.reads(true,true); adm.reportWrite(true);
  writeKyvernoPart(root,'admission',run,adm.observations,{tools:{}},'success');
  const {completeKyverno} = await import('./collectors/kyverno.mjs');
  const out = await completeKyverno({root});
  assert.equal(out.emitted,true,out.reason);
  validateResult(out.receipt,runBinding(root));
}

console.log('collectors.test PASS');
