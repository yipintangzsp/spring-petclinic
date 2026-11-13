import fs from 'node:fs';import path from 'node:path';
import {routeResultsHttp} from '../../../infra/security/manager-v2/router.mjs';
import {createHttpTransport} from '../../../infra/security/manager-v2/consumers/dojo-http.mjs';
import {DEFINITION} from '../../../infra/security/manager-v2/consumers/defectdojo.mjs';
const input=JSON.parse(fs.readFileSync(0,'utf8'));
const runId='web-042069ea-ae24-4f16-a914-4cbd8117aeaf',artifactDirectory=path.resolve('.devsecops/security-view-runs-v1',runId,'artifact');
const summary=JSON.parse(fs.readFileSync(path.join(artifactDirectory,'candidate-summary.json')));
const transport=createHttpTransport({enabled:true,targetId:'dojo-demo-java-v1',credentialFile:input.credentialFile,timeoutMs:10000,maxGetAttempts:2,backoffMs:100});
const args={run:{summary},artifactDirectory,expectedSealDigest:'1094e63bbdf6fa54950367ad94d113aa2fc3f40b0fc5e7b89f9f34d684f0ddd6',output:input.output,definitions:[DEFINITION],transport,journalDirectory:input.journalDirectory};
const result=await routeResultsHttp(args);
fs.writeFileSync(path.join(input.evidence,'delivery-reconciled.json'),JSON.stringify(result,null,2)+'\n',{flag:'wx'});
console.log(JSON.stringify({state:result.httpDelivery.deliveryState,receipts:result.httpDelivery.receipts.map(r=>({state:r.deliveryState,error:r.redactedError,httpStatus:r.httpStatus,test:r.remoteObjectReference}))}));
if(result.httpDelivery.deliveryState!=='ACKNOWLEDGED')process.exitCode=2;
else{
 const again=await routeResultsHttp(args);fs.writeFileSync(path.join(input.evidence,'idempotent.json'),JSON.stringify(again,null,2)+'\n',{flag:'wx'});
 if(again.httpDelivery.deliveryState!=='ACKNOWLEDGED'||again.httpDelivery.httpRequestCount!==0)throw Error('IDEMPOTENT_REDELIVERY_NOT_PROVEN');
 console.log('SAME_JOURNAL_REDELIVERY_VERIFIED_ZERO_HTTP');
}
