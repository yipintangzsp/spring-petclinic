import fs from 'node:fs';import crypto from 'node:crypto';
export const base='evidence/2026-11-02/zap-parent/';
export const sha=v=>crypto.createHash('sha256').update(v).digest('hex');
export const alert=(riskcode='3',pluginid='SYNTHETIC-HIGH')=>({pluginid,name:'Controlled passive alert',riskcode,confidence:'2',count:'1',instances:[{uri:'http://10.43.0.9:8080/owners/find',method:'GET',param:'fixture'}]});
export function fixture(){
 const image='registry.invalid/controlled@sha256:'+'a'.repeat(64),root='/fixture/tools';
 const files={'zap/zap-2.17.0.jar':'synthetic non-executable jar bytes','zap/addons/controlled.zap':'synthetic addon bytes'};
 const manifest=JSON.stringify({root,baseImage:JSON.parse(fs.readFileSync('infra/security/scanner-tools.json')).baseImage,files:[...Object.entries(files).map(([path,bytes])=>({path,sha256:sha(bytes)})),{path:'zap/current',symlink:'zap-2.17.0.jar'}]});
 return {env:{BUILD_NUMBER:'270',HEAVY_HOLDER:'fixture-holder',SECURITY_CLEANUP_SCAN_HOMES:'true',GATE_ZAP:'enforce',K8S_IMAGE:image},source:'a'.repeat(40),manifest,expectedManifestSha256:sha(manifest),toolFiles:files,symlinks:{'zap/current':'zap-2.17.0.jar'},lease:{spec:{holderIdentity:'fixture-holder'}},createdUid:'fixture-pod-uid',currentUid:'fixture-pod-uid',podIp:'10.42.0.9',canaryListen:true,canaryEvents:['connect'],isolationExits:[124,124],readinessExits:[0],transfer:{sourceExit:0,sinkExit:0},scanReports:{fixture:{site:[{'@host':'127.0.0.1',alerts:[alert('3','10062')]}]},'fixture-negative':{site:[{'@host':'127.0.0.1',alerts:[]}]},business:{site:[{'@host':'10.43.0.9',alerts:[]}]}},deployment:{spec:{template:{spec:{containers:[{image}]}}}},service:{spec:{clusterIP:'10.43.0.9',ports:[{port:8080}]}},auth:{status:'success',fixture:[{case:'synthetic-roles-only',status:200}],business:[{case:'public-get-observation',status:200}],productionUnsupported:['real identity model'],businessScope:'Existing public GET only'},confirmations:{schema:1,confirmations:[]},evidenceFiles:{},cleanupRemaining:false,commands:{},io:{}};
}
export function confirmation(r,patch={}){
 const a=r.scanReports.business.site[0].alerts[0]??alert();r.scanReports.business.site[0].alerts=[a];
 const proof={pluginid:a.pluginid,targetImage:r.deployment.spec.template.spec.containers[0].image,reportSha256:sha(JSON.stringify(r.scanReports.business)),uri:a.instances[0].uri,category:'xss',positiveValidated:true,negativeValidated:true,exploitConfirmed:true,evidenceVerified:false,evidencePath:'infra/security/dast-evidence/controlled-zap.json',expiresAt:'2035-01-01T00:00:00Z',...patch};
 const bytes=JSON.stringify({pluginid:proof.pluginid,targetImage:proof.targetImage,reportSha256:proof.reportSha256,uri:proof.uri,category:proof.category,positiveValidated:true,negativeValidated:true,exploitConfirmed:true});
 proof.evidenceSha256=sha(bytes);r.evidenceFiles[proof.evidencePath]=bytes;r.confirmations.confirmations=[proof];return proof;
}
