from pathlib import Path
import tempfile,runpy,json,shutil,sys
sys.dont_write_bytecode=True
O=Path(__file__).resolve().parent;b=runpy.run_path(str(O/'http-boundary.py'))
canary=O/'owned-http-boundary-canary-r2.txt'
with canary.open('x') as f:f.write('THIS ROUND HTTP BOUNDARY ONLY\n')
before=(canary.read_bytes(),canary.stat().st_mtime_ns,canary.stat().st_mode)
code=r'''
import fs from 'node:fs';import http from 'node:http';import net from 'node:net';
const checks={};for(const [k,f]of [['overwrite',()=>fs.writeFileSync(CANARY,'bad')],['delete',()=>fs.unlinkSync(CANARY)],['chmod',()=>fs.chmodSync(CANARY,0o666)]]){try{f();checks[k]='ALLOWED';}catch(e){checks[k]=e.code==='EPERM'?'DENIED':e.code;}}
const server=http.createServer((q,s)=>s.end('MOCK_BOUNDARY_ONLY'));await new Promise((ok,no)=>{server.once('error',no);server.listen(32185,'127.0.0.1',ok)});
checks.approvedLoopback=await new Promise((ok,no)=>http.get('http://127.0.0.1:32185/',s=>{s.resume();s.on('end',()=>ok(s.statusCode))}).on('error',no));
async function denied(host,port){return await new Promise(resolve=>{const s=net.connect({host,port});s.setTimeout(1000);s.on('connect',()=>{s.destroy();resolve('CONNECTED')});s.on('timeout',()=>{s.destroy();resolve('TIMEOUT_NOT_PROOF')});s.on('error',e=>resolve(e.code==='EPERM'?'DENIED':e.code));});}
checks.otherLoopback=await denied('127.0.0.1',32186);checks.external=await denied('192.0.2.1',443);
await new Promise(r=>server.close(r));fs.writeFileSync('disposable-output.json','{}');console.log(JSON.stringify(checks));
'''
with tempfile.TemporaryDirectory(prefix='security-cosign-boundary-') as d:
 t=Path(d).resolve();script=t/'probe.mjs';script.write_text('const CANARY='+json.dumps(str(canary))+';\n'+code)
 r=b['guarded'](t,[shutil.which('node'),str(script)]);assert r.returncode==0,r.stderr;x=json.loads(r.stdout)
 assert all(x[k]=='DENIED' for k in ['overwrite','delete','chmod','otherLoopback','external']) and x['approvedLoopback']==200,x
assert before==(canary.read_bytes(),canary.stat().st_mtime_ns,canary.stat().st_mode)
receipt={'classification':'REAL_OS_WRITE_AND_LOOPBACK_NETWORK_BOUNDARY','checks':x,'port':32185,'temporaryTreeRemoved':not Path(d).exists(),'historicalWriteProbes':0,'realDojoRequests':0}
with(O/'http-boundary-preflight.json').open('x') as f:json.dump(receipt,f,indent=2);f.write('\n')
print(json.dumps(receipt))
