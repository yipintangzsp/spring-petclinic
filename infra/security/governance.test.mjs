import test from 'node:test';import assert from 'node:assert/strict';import {summarizeKubescape,combineKubescape} from './governance/kubescape-report.mjs';import {governanceCounts} from './governance/dojo-client.mjs';
test('native Kubescape audit counts actual failed controls and deduplicates shared framework observations',()=>{const d={resources:[{}],summaryDetails:{complianceScore:50,controls:{a:{status:'failed'},b:{status:'passed'}}},results:[{resourceID:'pod/fixture',controls:[{controlID:'a',status:{status:'failed'},severity:'High'}]}]};const n=summarizeKubescape(d,'cluster','nsa'),c=summarizeKubescape(d,'cluster','cis');assert.equal(n.failedControlCount,1);assert.deepEqual(combineKubescape([n,c]),{failedControls:1,highRiskFindings:1,findings:1});assert.throws(()=>summarizeKubescape({},'cluster','nsa'));});
test('governance open severity excludes duplicate, accepted, closed and reviewed false positives',()=>{const a={active:true,severity:'High'};const c=governanceCounts([a,{...a,duplicate:true},{...a,false_p:true,active:false},{...a,risk_accepted:true,active:false},{...a,is_mitigated:true,active:false}]);assert.equal(c.open,1);assert.equal(c.severity.High,1);assert.equal(c.duplicates,1);assert.equal(c.acceptedRisk,1);assert.equal(c.mitigatedClosed,1);assert.equal(c.falsePositives,1);});

import {trivyCounts} from './governance/scan-counts.mjs';
test('a completed Trivy policy failure reports actual severity while engine failure stays unknown',()=>{
 const complete={status:'failed',failures:[{id:'fixture'}],scans:[{scan:{scan_status:'Success'},raw:{native:{vulnerabilities:[{severity:'High'},{severity:'Medium'}]}}}]};
 assert.deepEqual(trivyCounts(complete),{trivy_critical:0,trivy_high:1,trivy_medium:1,trivy_low:0});
 assert.equal(trivyCounts({...complete,failures:[]}),null);
 assert.equal(trivyCounts({...complete,scans:[{scan:{scan_status:'Error'}}]}),null);
 assert.equal(trivyCounts({...complete,scans:[{scan:{scan_status:'Success'},raw:{}}]}),null);
});
