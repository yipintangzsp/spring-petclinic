import test from 'node:test';import assert from 'node:assert/strict';
import {validateCI} from '../view/ci-intake.mjs';
const c={projectId:'python-fixture',commitSha:'1'.repeat(40),buildId:8};
const v={projectId:c.projectId,sourceRepository:'http://gitlab.devops.local/root/petclinic-platform.git',commitSha:c.commitSha,ciProvider:'jenkins',jobId:'security-gitlab-push-demo',buildId:8,trigger:'gitlab-webhook',pluginId:'gitleaks',scenarioId:'clean'};
test('versioned intake accepts exact fixed execution and distinguishes trigger from scan source',()=>{const r=validateCI(v,c);assert.equal(r.buildUrl,'http://jenkins.devops.local/job/security-gitlab-push-demo/8/');assert.equal(r.sourceScope,'FIXED_CLEAN_FIXTURE_NOT_GITLAB_CHECKOUT');});
for(const patch of [{projectId:'java-sbom-demo'},{pluginId:'sbom'},{scenarioId:'controlled-finding'},{path:'/tmp'},{commitSha:'2'.repeat(40)},{buildId:9},{sourceRepository:'http://other/repo.git'}])test('reject '+Object.keys(patch)[0],()=>assert.throws(()=>validateCI({...v,...patch},c)));
