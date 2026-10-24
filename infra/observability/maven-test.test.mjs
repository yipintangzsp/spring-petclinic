import {test} from 'node:test';
import assert from 'node:assert/strict';
import {ownsStoppedTest} from './maven-test.mjs';
const fixture=()=>({Id:'new',State:{Running:false},Config:{Labels:{'com.docker.compose.project':'petclinic-ci','com.docker.compose.service':'postgres','com.docker.compose.project.working_dir':'/workspace'}},Mounts:[{Type:'volume',Name:'new-volume'}]});
test('reclaims a new stopped PostgreSQL test owned by this workspace',()=>assert.equal(ownsStoppedTest(fixture(),new Set(['old']),new Set(['old-volume']),'/workspace'),true));
test('preserves pre-existing containers and data, live containers and foreign ownership',()=>{
 const original=fixture();assert.equal(ownsStoppedTest(original,new Set(['new']),new Set(),'/workspace'),false);
 assert.equal(ownsStoppedTest(original,new Set(),new Set(['new-volume']),'/workspace'),false);
 for(const changed of [
  {...original,State:{Running:true}},
  {...original,Config:{Labels:{...original.Config.Labels,'com.docker.compose.project':'business'}}},
  {...original,Config:{Labels:{...original.Config.Labels,'com.docker.compose.service':'mysql'}}}
 ])assert.equal(ownsStoppedTest(changed,new Set(),new Set(),'/workspace'),false);
 assert.equal(ownsStoppedTest(original,new Set(),new Set(),'/another-workspace'),false);
});
