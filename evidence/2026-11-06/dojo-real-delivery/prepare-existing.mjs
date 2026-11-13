import fs from 'node:fs';import path from 'node:path';
import {getRun,recentRuns} from '../../../infra/security/manager-v2/view/actions.mjs';
import {prepareDefectDojo} from '../../../infra/security/manager-v2/consumers/defectdojo.mjs';
import {digest} from '../../../infra/security/summary-v2/codec.mjs';
const output=path.resolve('evidence/2026-11-06/dojo-real-delivery');
const r=recentRuns().find(r=>r.pluginId==='semgrep'&&r.scenarioId==='controlled-finding'&&r.state==='COMPLETED'&&r.evidenceClass==='REAL');
if(!r)throw Error('NO_REAL_SEMGREP_FINDING_ARTIFACT');getRun(r.runId);
const artifactDirectory=path.resolve('.devsecops/security-view-runs-v1',r.runId,'artifact');
const summary=JSON.parse(fs.readFileSync(path.join(artifactDirectory,'candidate-summary.json')));
const before=fs.readFileSync(path.join(artifactDirectory,'candidate-summary.json'));
const plan=prepareDefectDojo({run:{summary},artifactDirectory,expectedSealDigest:r.artifactDigest});
if(!before.equals(fs.readFileSync(path.join(artifactDirectory,'candidate-summary.json'))))throw Error('SOURCE_MUTATED');
fs.writeFileSync(path.join(output,'offline-plan.json'),JSON.stringify(plan,null,2)+'\n',{flag:'wx'});
const record=plan.records.find(r=>r.pluginId==='semgrep'),item=plan.imports.find(i=>i.pluginId==='semgrep');
const proof={kind:'ReadOnlyRealArtifactMapping',at:new Date().toISOString(),runId:r.runId,evidenceClass:r.evidenceClass,policyDecision:r.policyDecision,evaluationCount:r.evaluationCount,resultDigest:r.resultDigest,artifactDigest:r.artifactDigest,executionTime:r.scannerCompletedAt,
 mappingStatus:record.mappingStatus,mappingReason:record.reason??null,findings:item?.payload.findings.map(f=>({ruleId:f.vuln_id_from_tool,severity:f.severity,sourceSeverity:JSON.parse(f.references).sourceSeverity,uniqueId:f.unique_id_from_tool,file:f.file_path,line:f.line}))??[],findingCount:item?.payload.findings.length??null,stableIdentitiesUnique:item?new Set(item.payload.findings.map(f=>f.unique_id_from_tool)).size===item.payload.findings.length:null,rawFactsUnchanged:true,planDigest:plan.planDigest,productionRequests:0,newScans:0};
fs.writeFileSync(path.join(output,'mapping.json'),JSON.stringify({...proof,receiptDigest:digest(proof)},null,2)+'\n',{flag:'wx'});
console.log(JSON.stringify(proof));
