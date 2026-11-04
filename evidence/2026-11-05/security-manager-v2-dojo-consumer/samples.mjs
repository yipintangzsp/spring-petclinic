// REPLAY only: import-boundary preparation from sealed prior real artifacts.
import fs from 'node:fs';import path from 'node:path';import {fileURLToPath} from 'node:url';
import {routeResults,CONSUMERS} from '../../../infra/security/manager-v2/router.mjs';
import {DEFINITION,prepareDefectDojo} from '../../../infra/security/manager-v2/consumers/defectdojo.mjs';
import {digest} from '../../../infra/security/summary-v2/codec.mjs';
const o=fileURLToPath(new URL('.',import.meta.url)),history=fileURLToPath(new URL('../security-manager-v2-cosign-real/real-linux/outputs/',import.meta.url));
const target=process.argv[2];fs.mkdirSync(target,{mode:0o700});const rows=[];
for(const name of ['H-gitleaks-fail','G-semgrep-fail','F-cosign-tampered','A-three-valid','D-gitleaks-disabled','C-semgrep-disabled','I-cosign-timeout','P-service-project','Q-cross-project-identity-rejected']){
 const dir=path.join(history,'attempt2-'+name),seal=JSON.parse(fs.readFileSync(path.join(dir,'candidate-seal.json'))),summary=JSON.parse(fs.readFileSync(path.join(dir,'candidate-summary.json'))),before=JSON.stringify(summary),out=path.join(target,name);fs.mkdirSync(out,{mode:0o700});
 const plan=prepareDefectDojo({run:{summary},artifactDirectory:dir,expectedSealDigest:digest(seal)});fs.writeFileSync(path.join(out,'plan.json'),JSON.stringify(plan,null,2)+'\n',{flag:'wx'});
 for(const i of plan.imports)fs.writeFileSync(path.join(out,i.pluginId+'.generic.json'),JSON.stringify(i.payload,null,2)+'\n',{flag:'wx'});
 const args={run:{summary},artifactDirectory:dir,expectedSealDigest:digest(seal),output:out,definitions:[CONSUMERS[0],DEFINITION]},delivery=routeResults(args),retry=routeResults(args);if(JSON.stringify(summary)!==before)throw Error('RESULT_MUTATED');
 fs.writeFileSync(path.join(out,'delivery.json'),JSON.stringify({classification:'REPLAY_OFFLINE_PREPARATION_NOT_HTTP_DELIVERY',delivery,retry,originalSummaryUnchanged:true,sourceArtifactSeal:digest(seal),sourceSummaryDigest:digest(summary)},null,2)+'\n',{flag:'wx'});
 rows.push({name,source:'PREVIOUS_REAL_CONTROLLED_EXECUTION_ARTIFACT_REPLAY',sourceArtifactSeal:digest(seal),sourceSummaryDigest:digest(summary),imports:plan.imports.map(i=>({pluginId:i.pluginId,findings:i.payload.findings.length,payloadDigest:i.payloadDigest,idempotencyKey:i.idempotencyKey})),deliveryDecision:delivery.receipts[1].deliveryDecision,retryReused:retry.receipts[1].reusedOfflinePayload,policyCounts:Object.fromEntries(summary.pluginResults.map(r=>[r.pluginId,r.evaluationCount])),resultDigests:delivery.receipts[1].resultDigests,factDigests:delivery.receipts[1].factDigests,sourceResultObjectsUnchanged:true});
}
fs.writeFileSync(path.join(target,'sample-index.json'),JSON.stringify({classification:'REPLAY_OF_PREVIOUS_REAL_RESULTS_NO_NEW_SCANS',rows,newScannerExecutions:0,consumerPolicyEvaluations:0,httpRequests:0,remoteIdempotency:'NOT_TESTED',remoteDelivery:'NOT_TESTED',promotionAllowed:false},null,2)+'\n',{flag:'wx'});console.log(JSON.stringify({samples:rows.length,scannerExecutions:0,httpRequests:0}));
