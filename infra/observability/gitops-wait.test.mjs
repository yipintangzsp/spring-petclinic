import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';

const script=fileURLToPath(new URL('./wait-gitops.sh',import.meta.url));
function run(overrides={}) {
 const dir=fs.mkdtempSync(path.join(os.tmpdir(),'gitops-race-'));
 fs.writeFileSync(path.join(dir,'kubectl'),`#!/bin/sh
case "$*" in
 *"get application"*)
  n=$(cat "$STATE/app" 2>/dev/null || echo 0); n=$((n+1)); echo "$n" > "$STATE/app"
  if [ "$n" -le "$API_FAILURES" ]; then exit 1; fi
  printf 'Synced Healthy %s' "$ARGO_REVISION" ;;
 *"get deployment"*)
  n=$(cat "$STATE/image" 2>/dev/null || echo 0); n=$((n+1)); echo "$n" > "$STATE/image"
  if [ "$n" -ge "$IMAGE_READY_AFTER" ]; then printf '%s' "$K8S_IMAGE"; else printf 'registry/petclinic:previous'; fi ;;
 *) exit 2 ;;
esac
`,{mode:0o700});
 try {
  const result=spawnSync('sh',[script,'target-revision'],{encoding:'utf8',timeout:5000,
   env:{...process.env,PATH:dir+path.delimiter+process.env.PATH,STATE:dir,
    K8S_IMAGE:'registry/petclinic:new',ARGO_REVISION:'target-revision',API_FAILURES:'0',
    IMAGE_READY_AFTER:'1',GITOPS_MAX_ATTEMPTS:'3',GITOPS_POLL_SECONDS:'0.01',
    ...overrides}});
  return {status:result.status,output:result.stdout,calls:Number(fs.readFileSync(path.join(dir,'image'),'utf8'))};
 } finally {fs.rmSync(dir,{recursive:true,force:true});}
}
test('Argo Synced arriving before the live image waits and succeeds',()=>{
 const r=run({IMAGE_READY_AFTER:'3'});assert.equal(r.status,0,r.output);assert.equal(r.calls,3);
});
test('live image alone cannot pass when Argo has another source revision',()=>{
 const r=run({ARGO_REVISION:'old-revision'});assert.equal(r.status,1);assert.equal(r.calls,3);
});
test('a temporary API outage does not prematurely fail or pass deployment',()=>{
 const r=run({API_FAILURES:'1'});assert.equal(r.status,0,r.output);assert.equal(r.calls,2);
});
test('a persistently wrong image fails when the bounded attempts end',()=>{
 const r=run({IMAGE_READY_AFTER:'99'});assert.equal(r.status,1);assert.match(r.output,/did not converge/);
});
