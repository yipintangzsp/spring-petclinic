import fs from 'node:fs';
import crypto from 'node:crypto';
const file='.devsecops/sbom.json', bytes=fs.readFileSync(file),bom=JSON.parse(bytes);
if(bom.bomFormat!=='CycloneDX'||bom.specVersion!=='1.6'||!Array.isArray(bom.components)||bom.components.length<10||!bom.dependencies?.length)throw Error('Nonempty CycloneDX 1.6 dependency inventory required');
const refs=bom.components.map(x=>x['bom-ref']);if(refs.some(x=>!x)||new Set(refs).size!==refs.length)throw Error('SBOM component references must be unique');
const summary={status:'success',source:fs.readFileSync('.git-sha','utf8').trim(),createdAt:new Date().toISOString(),format:bom.bomFormat,specVersion:bom.specVersion,components:refs.length,dependencyNodes:bom.dependencies.length,sha256:crypto.createHash('sha256').update(bytes).digest('hex'),scope:'Maven production dependencies; not OS packages, scanner or all platform images'};
fs.writeFileSync('.devsecops/sbom-summary.json',JSON.stringify(summary,null,2));console.log(JSON.stringify(summary));
