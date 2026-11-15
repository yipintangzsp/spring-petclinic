// T06: unified project authorization. Negative cases (no identity and
// cross-project identity) for execution / history / config / artifacts, plus
// the legitimate paths that must keep working. Uses a throwaway credentials
// file auto-generated inside this worktree's .devsecops/ (values never
// printed, directory is git-ignored runtime state).
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {projectAccess,accessCredentials,canReadRun,authorizeProject} from './view/project-access.mjs';
import {projectDefinitions,knownProject} from './project-registry.mjs';
import {projectControls} from './view/controls.mjs';
const dir=new URL('../../../.devsecops/',import.meta.url);
if(!fs.existsSync(dir))fs.mkdirSync(dir,{mode:0o755});
// The top-level suite seeds a controls fixture into this throwaway state with
// default (loose) permissions; production persist() always maintains 0600 and
// raw() rejects anything looser. Normalize the fixture mode so the controls
// path can be exercised here.
const controlsFile=new URL('security-view-controls-v1.json',dir);
if(fs.existsSync(controlsFile))fs.chmodSync(controlsFile,0o600);
const credentials=accessCredentials();
const access=projectAccess();
const A='java-sbom-demo',B='java-sbom-demo-b',CI='python-fixture';
const anon={headers:{}};
const asOperator={headers:{authorization:'Bearer '+credentials.operatorToken}};
const asA={headers:{'x-project-token':credentials.projects[A]}};
const asB={headers:{'x-project-token':credentials.projects[B]}};
const sbomRunA={pluginId:'sbom',projectId:A};
const ciRun={pluginId:'gitleaks',projectId:CI,ciContext:{projectId:CI}};
test('registry: one merged project definition source (sbom + ci)',()=>{
 const d=projectDefinitions();
 assert.equal(Object.hasOwn(d,A),true);assert.equal(Object.hasOwn(d,B),true);assert.equal(Object.hasOwn(d,CI),true);
 assert.equal(knownProject(A),true);assert.equal(knownProject('no-such-project'),false);
});
test('registry: controls resolve through the same definitions',()=>{
 assert.equal(projectControls(A).projectId,A);
 assert.equal(projectControls(CI).pluginId,'gitleaks');
 assert.throws(()=>projectControls('no-such-project'),/PROJECT_NOT_AUTHORIZED/);
});
test('execute: anonymous identity is rejected',()=>{
 assert.equal(authorizeProject(anon,A,'execute',access),false);
 assert.equal(authorizeProject(anon,CI,'execute',access),false);
});
test('execute: cross-project identity is rejected',()=>{
 assert.equal(authorizeProject(asB,A,'execute',access),false);
 assert.equal(authorizeProject(asA,B,'execute',access),false);
 assert.equal(authorizeProject(asA,CI,'execute',access),false);
});
test('execute: legitimate identities keep working',()=>{
 assert.equal(authorizeProject(asA,A,'execute',access),true);
 assert.equal(authorizeProject(asOperator,A,'execute',access),true);
 assert.equal(authorizeProject(asOperator,CI,'execute',access),true);
});
test('history: anonymous and cross-project reads of sbom runs are rejected',()=>{
 assert.equal(canReadRun(anon,sbomRunA,access),false);
 assert.equal(canReadRun(asB,sbomRunA,access),false);
 assert.equal(authorizeProject(anon,A,'history',access),false);
 assert.equal(authorizeProject(asB,A,'history',access),false);
});
test('history: legitimate reads keep working; ci runs stay operator-only',()=>{
 assert.equal(canReadRun(asA,sbomRunA,access),true);
 assert.equal(canReadRun(asOperator,sbomRunA,access),true);
 assert.equal(canReadRun(anon,ciRun,access),false);
 assert.equal(canReadRun(asA,ciRun,access),false);
 assert.equal(canReadRun(asOperator,ciRun,access),true);
});
test('config: anonymous and cross-project identities are rejected',()=>{
 assert.equal(authorizeProject(anon,A,'config',access),false);
 assert.equal(authorizeProject(asB,A,'config',access),false);
 assert.equal(authorizeProject(asA,A,'config',access),true);
 assert.equal(authorizeProject(asOperator,CI,'config',access),true);
});
test('artifact: anonymous and cross-project identities are rejected',()=>{
 assert.equal(authorizeProject(anon,A,'artifact',access),false);
 assert.equal(authorizeProject(asB,A,'artifact',access),false);
 assert.equal(authorizeProject(asA,A,'artifact',access),true);
 assert.equal(authorizeProject(asOperator,CI,'artifact',access),true);
});
test('unknown actions fail closed even for the operator',()=>{
 assert.equal(authorizeProject(asOperator,A,'delete',access),false);
 assert.equal(authorizeProject(asOperator,A,'',access),false);
});
