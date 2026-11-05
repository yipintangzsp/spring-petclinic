// Test-only REPLAY copies and explicitly resealed FIXTURE variants. No scans.
import fs from 'node:fs';import path from 'node:path';
import {artifactStore,sealResult} from '../result.mjs';
import {digest} from '../../summary-v2/codec.mjs';
const history=new URL('../../../../evidence/2026-11-05/security-manager-v2-cosign-real/real-linux/outputs/',import.meta.url).pathname;
export function replay(name){const dir=path.join(history,'attempt2-'+name);return {dir,summary:JSON.parse(fs.readFileSync(path.join(dir,'candidate-summary.json'))),expected:digest(JSON.parse(fs.readFileSync(path.join(dir,'candidate-seal.json'))))};}
export function variant(parent,name,{mutate=null,mixed=false}={}){
 const x=replay(name),seal=JSON.parse(fs.readFileSync(path.join(x.dir,'candidate-seal.json'))),data={};
 for(const n of Object.keys(seal.files))if(n!=='candidate-summary.json'&&!n.endsWith('.result.json'))data[n]=fs.readFileSync(path.join(x.dir,n),'utf8');
 const summary=structuredClone(x.summary);
 summary.pluginResults=summary.pluginResults.map(original=>{
  let r=structuredClone(original);
  if(mixed&&r.pluginId==='semgrep'){
   const other=replay('G-semgrep-fail');r=structuredClone(other.summary.pluginResults.find(p=>p.pluginId==='semgrep'));
   r.runId=summary.runId;r.runtimeFacts.validationRunId=summary.runId;
   for(const suffix of ['raw.json','facts.json'])data['semgrep.'+suffix]=fs.readFileSync(path.join(other.dir,'semgrep.'+suffix),'utf8');
  }
  mutate?.(r);const {resultDigest,...body}=r;return sealResult(body);
 });
 const dir=path.join(parent,'variant-'+fs.readdirSync(parent).length),store=artifactStore(dir);
 for(const [n,raw]of Object.entries(data))store.putRaw(n,raw);
 for(const r of summary.pluginResults)store.put(r.pluginId+'.result.json',r);
 store.put('candidate-summary.json',summary);return {dir,summary,expected:store.finish().sealDigest};
}
