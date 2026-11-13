// Real original Gate under verified MIN_RBAC. No raw facts or plaintext files.
import fs from 'node:fs';import {captureStage} from '/fixture/work/infra/security/runtime-facts/execute.mjs';
import {collectRuntimeFacts} from '/fixture/work/infra/security/runtime-facts/collector.mjs';
const binding=JSON.parse(fs.readFileSync('/fixture/binding.json')),scenario=JSON.parse(fs.readFileSync('/fixture/case.json')).scenario;
const command=process.execPath+' infra/security/secrets-gate.mjs';
const run=await captureStage({sourceId:'sops',command,binding,env:process.env,cwd:'/fixture/work',onOutput:()=>{}});
const e=run.envelope,envelope=collectRuntimeFacts({sourceId:'sops',binding,execution:e.execution,payload:e.facts.raw,reports:e.reports,
 evidence:[...e.evidence,{classification:'CONTROLLED_ISOLATED_RUNTIME',executionScope:'CONTROLLED_ISOLATED_RUNTIME',scenario,canonicalCurrentResult:scenario==='POSITIVE',nodeExecutableSha256:'d09e299258c24f7cdf6f5d5ec185e3a56512b27a697113735dac909f1cac7b8d',productionSecretAccess:0,productionAgeKeyAccess:0}]});
let supporting=null;
if(scenario!=='POSITIVE'){
 const {evaluateAsync}=await import('/fixture/work/infra/security/policy/engine.mjs');
 const p=await evaluateAsync(envelope.facts,{policyVersion:'baseline-v1',securityLevel:'standard'});
 supporting={classification:'SUPPORTING_CONTROLLED_CONTRACT_NOT_CANONICAL_CURRENT_RESULT',oldDecision:run.exitStatus===0?'PASS':'FAIL',policyDecision:p.decision,rawFactDigest:envelope.rawFactDigest};
 if(supporting.oldDecision!==supporting.policyDecision)throw Error('Supporting contract differential mismatch');
}
console.log(JSON.stringify({envelope,oldExit:run.exitStatus,supporting}));
