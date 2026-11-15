import fs from 'node:fs';
import crypto from 'node:crypto';
import {valuesDigest} from './contract.mjs';

// Approval-time Helm binding, sourced from the Gate's helm shadow products.
// The shadow pipeline is the Gate's proof that the chart+values were rendered
// and validated for this build: status.json carries the render verdict and the
// rendered output hash, rendered.yaml is that output. The chart emits no
// version label into the render, so the version is read from the exact chart
// the shadow rendered, and valuesSha256 pins the exact values file it
// consumed; status.json also carries the sha256 fingerprints of the exact
// Chart.yaml and values file the render consumed, and this helper refuses
// (fail closed) when the build identity on either side is missing, when the
// fingerprints are absent (legacy products), or when the current chart/values
// no longer match them; promote.mjs later refuses to deploy anything else
// (validateHelmBinding). Returns null when the Gate ran without the helm
// shadow (no .helm-shadow/status.json): legacy approvals stay byte-identical.
// Throws when shadow products exist but are unusable, stale, or tampered —
// an approval must never silently drop a binding its Gate produced.
export function helmBindingFromShadow(env=process.env){
 const statusPath='.helm-shadow/status.json';
 if(!fs.existsSync(statusPath))return null;
 const status=JSON.parse(fs.readFileSync(statusPath,'utf8'));
 if(status.mode!=='SHADOW_ONLY'||status.HELM_RENDER_STATUS!=='PASS'||!/^[a-f0-9]{64}$/.test(status.renderedSha256||''))throw Error('Helm shadow products unusable for approval binding');
 if(!env.BUILD_NUMBER||!status.validationBuild)throw Error('Helm shadow build identity missing for approval binding');
 if(String(status.validationBuild)!==String(env.BUILD_NUMBER))throw Error('Helm shadow products belong to another build');
 const rendered=fs.readFileSync('.helm-shadow/rendered.yaml','utf8');
 if(crypto.createHash('sha256').update(rendered).digest('hex')!==status.renderedSha256)throw Error('Helm shadow rendered output differs from Gate record');
 if(!/^[a-f0-9]{64}$/.test(status.chartSha256||'')||!/^[a-f0-9]{64}$/.test(status.valuesSha256||''))throw Error('Helm shadow products lack render input fingerprints');
 const chartPath=env.HELM_CHART_PATH||'charts/petclinic';
 const chartText=fs.readFileSync(chartPath+'/Chart.yaml','utf8');
 if(crypto.createHash('sha256').update(chartText).digest('hex')!==status.chartSha256)throw Error('Helm shadow render inputs differ from current chart/values');
 const chartVersion=(chartText.match(/^version:[ \t]*(\S+)[ \t]*$/m)||[])[1];
 if(!/^[0-9]+\.[0-9]+\.[0-9]+$/.test(chartVersion||''))throw Error('Chart version unreadable for approval binding');
 const valuesPath=env.HELM_VALUES_FILE||'charts/petclinic/values-prod.yaml';
 const valuesText=fs.readFileSync(valuesPath,'utf8');
 if(crypto.createHash('sha256').update(valuesText).digest('hex')!==status.valuesSha256)throw Error('Helm shadow render inputs differ from current chart/values');
 valuesDigest(valuesText);
 return {chart:'petclinic',valuesFile:'charts/petclinic/values-prod.yaml',chartVersion,valuesSha256:'sha256:'+crypto.createHash('sha256').update(valuesText).digest('hex')};
}
