// Fixed trusted dispatcher only. SSH forced command is the authorization boundary.
import fs from 'node:fs';
import path from 'node:path';
import {randomUUID} from 'node:crypto';
import {execFileSync} from 'node:child_process';
import {acceptLinuxGitleaksPacket} from '../../security/manager-v2/view/linux-gitleaks.mjs';
import {digest} from '../../security/summary-v2/codec.mjs';
const required=(ok,code)=>{if(!ok)throw Error(code);};
required(process.platform==='linux'&&process.getuid()!==0,'LINUX_NONROOT_JENKINS_REQUIRED');
required(process.env.DEMO_JOB==='security-gitlab-push-demo'&&/^[1-9][0-9]*$/.test(process.env.DEMO_BUILD??'')&&
 /^[a-f0-9]{40}$/.test(process.env.DEMO_COMMIT??''),'BUILD_IDENTITY_REQUIRED');
const key=process.env.DEMO_SSH_KEY;
required(typeof key==='string'&&path.isAbsolute(key)&&fs.lstatSync(key).isFile()&&
 fs.statSync(key).uid===process.getuid()&&!(fs.statSync(key).mode&0o077),'PRIVATE_KEY_FILE_BOUNDARY');
const runId='web-'+randomUUID();
fs.mkdirSync('evidence',{mode:0o700});
const known='192.168.1.58 ssh-ed25519 @TRUSTED_HOST_KEY@\n';
fs.writeFileSync('known_hosts',known,{flag:'wx',mode:0o400});
const args=['-F','/dev/null','-T','-n','-i',key,
 '-o','BatchMode=yes','-o','IdentitiesOnly=yes','-o','IdentityAgent=none',
 '-o','PreferredAuthentications=publickey','-o','PasswordAuthentication=no','-o','KbdInteractiveAuthentication=no',
 '-o','StrictHostKeyChecking=yes','-o','UpdateHostKeys=no','-o','HostKeyAlias=192.168.1.58',
 '-o','UserKnownHostsFile='+path.resolve('known_hosts'),'-o','GlobalKnownHostsFile=/dev/null',
 '-o','HostKeyAlgorithms=ssh-ed25519','-o','ClearAllForwardings=yes',
 '-o','ConnectTimeout=5','-o','ConnectionAttempts=1','-o','ServerAliveInterval=4','-o','ServerAliveCountMax=2',
 'security-gitleaks@192.168.64.11','clean-v1 '+runId];
const start=new Date().toISOString();
let packet;
try{
 const stdout=execFileSync('/usr/bin/ssh',args,{input:'',encoding:'utf8',timeout:29000,maxBuffer:524288,
  env:{PATH:'/usr/bin:/bin',LANG:'C'}});
 packet=JSON.parse(stdout);
}catch(e){throw Error('RESTRICTED_GITLEAKS_TRANSPORT_OR_EXECUTION_FAILED');}
const scan=acceptLinuxGitleaksPacket(packet,'clean',runId,path.resolve('evidence'));
required(scan.scannerExecuted===true&&scan.scannerExitCode===0&&scan.findingsCount===0&&
 scan.evaluationCount===1&&scan.policyDecision==='PASS'&&scan.cleanup==='VERIFIED','CLEAN_EVIDENCE_REQUIRED');
const body={kind:'JenkinsGitLabGitleaksEvidence',classification:'REAL_CONTROLLED_EXECUTION',
 job:process.env.DEMO_JOB,build:Number(process.env.DEMO_BUILD),commit:process.env.DEMO_COMMIT,
 branch:'security-demo/gitlab-push-20261105',dispatchStartedAt:start,dispatchCompletedAt:new Date().toISOString(),
 runId,scenarioId:'clean',...scan,releaseCount:0,rolloutCount:0};
const receipt={...body,receiptDigest:digest(body)};
fs.writeFileSync('evidence/jenkins-gitleaks-receipt.json',JSON.stringify(receipt,null,2)+'\n',{flag:'wx',mode:0o400});
console.log(JSON.stringify({runId,scannerExitCode:scan.scannerExitCode,findingsCount:scan.findingsCount,
 policyDecision:scan.policyDecision,evaluationCount:scan.evaluationCount,resultDigest:scan.resultDigest}));
