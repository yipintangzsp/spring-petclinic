import fs from 'node:fs';import crypto from 'node:crypto';
export const base='evidence/2026-11-01/gitleaks-parent/';
export const sha=x=>crypto.createHash('sha256').update(x).digest('hex');
export function fixture(){
 const lock=fs.readFileSync('infra/security/tools-lock.json','utf8'),image=JSON.parse(lock).gitleaks.image;
 return {source:'a'.repeat(40),toolLock:lock,env:{BUILD_NUMBER:'270',HEAVY_HOLDER:'fixture-holder'},lease:{spec:{holderIdentity:'fixture-holder'}},createdUid:'fixture-pod-uid',podUids:[],imageId:image,resources:{requests:{cpu:'100m',memory:'256Mi'},limits:{cpu:'1',memory:'512Mi'}},interfaces:{eth0:[{family:'IPv4',address:'10.42.0.9'}]},canaryListen:true,canaryEvents:['connect'],ncHelp:'nc -z zero-I/O',isolationExits:[1,1],nodeNetworkExit:1,effectiveUid:'65532',readOnlyExit:1,readOnlyStderr:'read-only file system',memoryPeak:'33554432',scans:{'/work/fixture':{exit:1},'/work/clean':{exit:0},'/work/source':{exit:0}},reportFiles:{'/work/positive.json':JSON.stringify([{RuleID:'github-pat',File:'/work/fixture/test.txt',StartLine:1,Fingerprint:'synthetic-fixture',Secret:'[REDACTED]'}]),'/work/clean.json':'[]','/work/source.json':'[]'},sourceText:{'/work/source/a.txt':'public checksum fixture'},reviewedEntries:[],cleanupRemaining:false,io:{},commands:{}};
}
export function sourceFinding(r,{reviewed=false,duplicate=false}={}){
 const finding={RuleID:'fixture-rule',File:'/work/source/a.txt',StartLine:1,Fingerprint:'synthetic-location',Description:'Non-secret controlled metadata',Secret:'[REDACTED]',Tags:['fixture'],Entropy:0};
 r.scans['/work/source'].exit=1;r.reportFiles['/work/source.json']=JSON.stringify(duplicate?[finding,{...finding}]:[finding]);
 if(reviewed)r.reviewedEntries=[{path:'a.txt',rule:'fixture-rule',line_sha256:sha(r.sourceText['/work/source/a.txt']),reason:'controlled public checksum'}];
}
