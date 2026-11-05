// Restricted versioned query templates; not a general LogQL parser/evaluator.
import {freeze} from '../../summary-v2/codec.mjs';
export const SELECTOR='{service_name="security-manager-v2",environment="validation",schema_version="1",job="devsecops-security-v2"}';
const fields=['eventType','projectId','runId','resultDigest','artifactDigest','executionStatus','policyDecision','evaluationCount','findingCount','findingCountKnown','highSeverityFindingCount','highSeverityCountKnown','consumerId','deliveryStatus','deliveryOrigin','errorCategory','sourceClassification','timestamp','pluginId'];
const parse=' | json '+fields.map(k=>k+'="'+k+'"').join(', ')+' | __error__=""';
const project=' | projectId=${project:json}',run=' | runId=${run:json}';
const scoped=SELECTOR+parse+project+run;
const plugins=scoped+' | eventType="PLUGIN_RESULT"';
const metric=(field,extra='')=>'max by (plugin) (max_over_time('+plugins+extra+' | unwrap '+field+' | __error__="" [$__range]))';
export const QUERIES=freeze([
 {id:'execution',panel:1,kind:'logs',expr:plugins,purpose:'Execution state and Policy decision remain separate JSON fields; REPLAY, not a new scan.'},
 {id:'policy',panel:2,kind:'metric',expr:'sum by (policy_decision) (max by (plugin, policy_decision) (max_over_time('+plugins+' | policy_decision!="NONE" | unwrap evaluationCount | __error__="" [$__range])))',purpose:'One completed evaluation per plugin in exact selected project/run; duplicate deliveries do not increase counts.'},
 {id:'findings',panel:3,kind:'metric',expr:metric('findingCount',' | findingCountKnown="true"'),purpose:'Native count only. Disabled/error/not-scanned/Cosign produce no value, never zero.'},
 {id:'high-findings',panel:3,kind:'metric',expr:metric('highSeverityFindingCount',' | highSeverityCountKnown="true"'),purpose:'Only known native HIGH/CRITICAL. Gitleaks has no native severity; Semgrep ERROR is not silently HIGH.'},
 {id:'availability',panel:4,kind:'logs',expr:plugins+' | executionStatus=~"DISABLED|SKIPPED|NOT_CONFIGURED|UNSUPPORTED|ERROR|POLICY_ERROR"',purpose:'Absence of a row is no observation, not PASS.'},
 {id:'delivery',panel:5,kind:'logs',expr:scoped+' | eventType="CONSUMER_DELIVERY"',purpose:'Show Dojo/Loki receipt states and MOCK_HTTP/DRY_RUN/LOCAL_ONLY origin. No claim of real remote ACK.'},
 {id:'project',panel:6,kind:'logs',expr:SELECTOR+parse+project+' | eventType="PLUGIN_RESULT"',purpose:'Selected project across runs; 200-row limit. Repeated rows are deliveries, not independent scans.'},
 {id:'provenance',panel:7,kind:'logs',expr:SELECTOR+parse+project+' | (runId=${run:json} or resultDigest=${resultDigest:json})',purpose:'Exact run or digest match, within project. No source snippets or secrets.'}
]);
export function validateQueryContract(query){
 const expected=QUERIES.find(q=>q.id===query.id);if(!expected||JSON.stringify(query)!==JSON.stringify(expected))throw Error('QUERY_TEMPLATE_MISMATCH');
 const e=query.expr;if(!e.includes(SELECTOR)||!e.includes('projectId=${project:json}')||/count_over_time|rate\(|sum_over_time|job="devsecops"/.test(e))throw Error('QUERY_SCOPE_OR_DUPLICATE_COUNT');
 let quoted=false,escape=false;const stack=[];for(const c of e){if(escape){escape=false;continue;}if(quoted&&c==='\\'){escape=true;continue;}if(c==='"'){quoted=!quoted;continue;}if(quoted)continue;if('({['.includes(c))stack.push(c);if(')}]'.includes(c)&&stack.pop()!=='({['[')}]'.indexOf(c)])throw Error('QUERY_STRUCTURE');}if(quoted||stack.length)throw Error('QUERY_STRUCTURE');
 if(query.kind==='metric'&&(!e.includes('| unwrap ')||!e.includes('max_over_time')||!e.includes('runId=${run:json}')||!e.includes('| __error__="" [$__range]')))throw Error('METRIC_CONTRACT');return true;
}
// Independent fixture data projection, NOT a Loki server query execution.
export function fixtureView(events,{projectId,runId,resultDigest=''}){
 const rows=events.filter(e=>e.projectId===projectId),selected=rows.filter(e=>e.runId===runId),unique=new Map();
 for(const e of selected.filter(e=>e.eventType==='PLUGIN_RESULT')){const old=unique.get(e.eventIdentity);if(old&&JSON.stringify(old)!==JSON.stringify(e))throw Error('FIXTURE_IDENTITY_CONFLICT');unique.set(e.eventIdentity,e);}
 const plugins=[...unique.values()],policy={},findings={},high={};for(const e of plugins){if(e.policyDecision!==null)policy[e.policyDecision]=(policy[e.policyDecision]??0)+1;if(e.findingCountKnown)findings[e.pluginId]=e.findingCount;if(e.highSeverityCountKnown)high[e.pluginId]=e.highSeverityFindingCount;}
 return {classification:'OFFLINE_DATA_CONTRACT_NOT_LOKI_QUERY',plugins,policy,findings,high,availability:plugins.filter(e=>!['COMPLETED'].includes(e.executionStatus)),deliveries:selected.filter(e=>e.eventType==='CONSUMER_DELIVERY'),provenance:rows.filter(e=>e.runId===runId||e.resultDigest===resultDigest)};
}
