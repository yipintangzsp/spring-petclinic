import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import {waitGitLabReady} from './service-readiness.mjs';

async function server(handler, run) {
 const app=http.createServer(handler);
 await new Promise(resolve=>app.listen(0,'127.0.0.1',resolve));
 try {await run(`http://127.0.0.1:${app.address().port}`);}
 finally {app.closeAllConnections();await new Promise(resolve=>app.close(resolve));}
}
const quick={timeoutMs:500,pollMs:10,requestTimeoutMs:100};
test('waits for authenticated Rails API recovery without an IP allowlist change',async()=>{
 let calls=0;
 await server((req,res)=>{
  assert.equal(req.url,'/api/v4/user');assert.equal(req.headers['private-token'],'synthetic-test-token');
  calls++;res.statusCode=calls<3?503:200;res.end(calls<3?'startup':JSON.stringify({id:1,username:'synthetic-test'}));
 },async base=>{const user=await waitGitLabReady(base,{...quick,headers:{'PRIVATE-TOKEN':'synthetic-test-token'}});assert.equal(user.id,1);assert.equal(calls,3);});
});
test('a listening nginx with unhealthy Rails cannot pass',async()=>{
 await server((req,res)=>res.end(JSON.stringify({status:'failed'})),async base=>{
  await assert.rejects(waitGitLabReady(base,{...quick,timeoutMs:70}),/timed out/);
 });
});
test('access errors fail without repeatedly polling',async()=>{
 let calls=0;
 await server((req,res)=>{calls++;res.statusCode=403;res.end('forbidden');},async base=>{
  await assert.rejects(waitGitLabReady(base,quick),/HTTP 403/);assert.equal(calls,1);
 });
});
test('hung responses terminate within the readiness budget',async()=>{
 await server(()=>{},async base=>{
  const start=Date.now();
  await assert.rejects(waitGitLabReady(base,{...quick,timeoutMs:70}),/timed out/);
  assert.ok(Date.now()-start<1000);
 });
});
