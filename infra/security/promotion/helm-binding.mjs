import fs from 'node:fs';
import crypto from 'node:crypto';
import {valuesDigest} from './contract.mjs';

// Approval-time Helm binding, sourced from the Gate's helm shadow products.
// The shadow pipeline is the Gate's proof that the chart+values were rendered
// and validated for this build: status.json carries the render verdict and the
// rendered output hash, rendered.yaml is that output. The chart emits no
// version label into the render, so the version is read from the exact chart
// the shadow rendered, and valuesSha256 pins the exact values file it
// consumed; promote.mjs later refuses to deploy anything else
// (validateHelmBinding). Returns null when the Gate ran without the helm
// shadow (no .helm-shadow/status.json): legacy approvals stay byte-identical.
// Throws when shadow products exist but are unusable, stale, or tampered —
// an approval must never silently drop a binding its Gate produced.
export function helmBindingFromShadow(env=process.env){
 const statusPath='.helm-shadow/status.json';
 if(!fs.existsSync(statusPath))return null;
 const status=JSON.parse(fs.readFileSync(statusPath,'utf8'));
 if(status.mode!=='SHADOW_ONLY'||status.HELM_RENDER_STATUS!=='PASS'||!/^[a-f0-9]{64}$/.test(status.renderedSha256||''))throw Error('Helm shadow products unusable for approval binding');
 if(env.BUILD_NUMBER&&status.validationBuild&&String(status.validationBuild)!==String(env.BUILD_NUMBER))throw Error('Helm shadow products belong to another build');
 const rendered=fs.readFileSync('.helm-shadow/rendered.yaml','utf8');
 if(crypto.createHash('sha256').update(rendered).digest('hex')!==status.renderedSha256)throw Error('Helm shadow rendered output differs from Gate record');
 const chartPath=env.HELM_CHART_PATH||'charts/petclinic';
 const chartVersion=(fs.readFileSync(chartPath+'/Chart.yaml','utf8').match(/^version:[ \t]*(\S+)[ \t]*$/m)||[])[1];
 if(!/^[0-9]+\.[0-9]+\.[0-9]+$/.test(chartVersion||''))throw Error('Chart version unreadable for approval binding');
 const valuesPath=env.HELM_VALUES_FILE||'charts/petclinic/values-prod.yaml';
 const valuesText=fs.readFileSync(valuesPath,'utf8');
 valuesDigest(valuesText);
 return {chart:'petclinic',valuesFile:'charts/petclinic/values-prod.yaml',chartVersion,valuesSha256:'sha256:'+crypto.createHash('sha256').update(valuesText).digest('hex')};
}
