// CONTROLLED UNIT FIXTURES ONLY. No runtime scanner/source evidence is asserted.
import fs from 'node:fs';
import {EXPECTED_SOURCES} from './inventory.mjs';
import {createSourceOwner} from './owner.mjs';
import {finalizeArtifact,encodeArtifact} from './artifact.mjs';

export const root = new URL('../../../',import.meta.url).pathname.replace(/\/$/,'');
export const contract = () => JSON.parse(fs.readFileSync(new URL('./candidate-integrity.json',import.meta.url)));
export const binding = Object.freeze({job:'isolated-policy-test',build:1,project:'fixture',source:'c'.repeat(40),candidate:'registry.invalid/fixture@sha256:'+'a'.repeat(64),targetScope:'candidate',runId:'controlled-run-1'});
export const inputFor = state => ({component:'trivy',status:({SKIPPED:'skipped',NOT_CONFIGURED:'not_configured',ERROR:'error'})[state]??'success',
  raw:{findings:state === 'FAIL'?[{id:'FIXTURE-HIGH',severity:'High'}]:state === 'WARN'?[{id:'FIXTURE-MEDIUM',severity:'Medium'}]:[],review:{entries:[]},image:binding.candidate}});
export async function fixture(state='PASS',config={},legacySummary=null) {
  const c = contract(),producer = c.versions.V2.producer,bound = {...binding,project:legacySummary?.project??binding.project},owner = createSourceOwner(bound),sources = [];
  for (const sourceId of EXPECTED_SOURCES) sources.push(await owner.evaluateOnce(sourceId,sourceId === 'trivy'?inputFor(state):{component:sourceId,status:'skipped',raw:{fixture:'explicit controlled skip'}},config));
  const aggregate = {finalized:true,sources:Object.fromEntries(sources.map(r => [r.sourceId,{resultDigest:r.resultDigest,
    observedStatus:r.error?'failed':r.result.decision==='FAIL'?'failed':r.result.decision==='WARN'?'warn':r.result.status==='SKIPPED'?'skipped':r.result.status==='NOT_CONFIGURED'?'not_configured':'success'}])),
    externalChecks:{snapshotBefore:'success',readOnlyReleaseVerification:'success'},inheritedBuildResult:'SUCCESS',result:sources.some(r => r.error || r.result.decision==='FAIL')?'FAILURE':'SUCCESS'};
  const legacy = legacySummary??{schema:1,project:binding.project,pipeline:'security-audit',build:binding.build,source:binding.source,auditTargetImage:binding.candidate,targetScope:binding.targetScope,build_result:aggregate.result,recorded_at:'2026-11-02T00:00:00Z',missing:[]};
  const artifact = finalizeArtifact({binding:bound,sources,aggregate,legacySummary:legacy,producer}),packet = encodeArtifact(artifact);
  return {owner,sources,aggregate,artifact,packet,context:{digest:packet.digest,binding:bound,producer,integrity:{root,contract:c}}};
}
