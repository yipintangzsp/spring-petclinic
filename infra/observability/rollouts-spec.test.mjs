import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
const items=JSON.parse(fs.readFileSync(new URL('../devops-lab/rollouts/resources.json',import.meta.url))).items;
function validate(item){
 const canary=item.spec.strategy.canary;
 if(canary?.scaleDownDelaySeconds!==undefined&&!canary.trafficRouting)throw Error('Canary delay requires traffic routing');
}
test('committed lab strategies are valid for their traffic mode',()=>{
 for(const item of items.filter(x=>x.kind==='Rollout'))validate(item);
});
test('delay without traffic routing is rejected; blue-green delay remains valid',()=>{
 assert.throws(()=>validate({spec:{strategy:{canary:{scaleDownDelaySeconds:10}}}}),/traffic routing/);
 assert.doesNotThrow(()=>validate({spec:{strategy:{blueGreen:{scaleDownDelaySeconds:10}}}}));
 assert.doesNotThrow(()=>validate({spec:{strategy:{canary:{scaleDownDelaySeconds:10,trafficRouting:{}}}}}));
});
