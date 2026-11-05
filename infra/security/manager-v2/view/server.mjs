import http from 'node:http';
import fs from 'node:fs';
import {overview} from './data.mjs';
const instance = process.env.SECURITY_VIEW_INSTANCE ?? 'foreground';
const assets = new Map([['/', ['index.html','text/html; charset=utf-8']], ['/app.js',['app.js','text/javascript; charset=utf-8']], ['/style.css',['style.css','text/css; charset=utf-8']]]);
const server = http.createServer((req,res) => {
  const headers = {'Cache-Control':'no-store','X-Content-Type-Options':'nosniff',
    'Content-Security-Policy':"default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
    'Referrer-Policy':'no-referrer'};
  const send=(code,type,body)=>{res.writeHead(code,{...headers,'Content-Type':type});res.end(req.method==='HEAD'?'':body);};
  if (!['127.0.0.1:17862','localhost:17862'].includes(req.headers.host)) return send(403,'text/plain','Local host required');
  if (!['GET','HEAD'].includes(req.method)) return send(405,'text/plain','Read only');
  if (req.headers.origin && !['http://127.0.0.1:17862','http://localhost:17862'].includes(req.headers.origin)) return send(403,'text/plain','Origin rejected');
  const url = new URL(req.url,'http://127.0.0.1:17862');
  try {
    if (url.pathname==='/api/health') return send(200,'application/json',JSON.stringify({service:'security-manager-v2-readonly',instance,pid:process.pid}));
    if (url.pathname==='/api/overview') return send(200,'application/json',JSON.stringify(overview()));
    const asset = assets.get(url.pathname);
    if (!asset) return send(404,'text/plain','Not found');
    send(200,asset[1],fs.readFileSync(new URL(asset[0],import.meta.url)));
  } catch { send(503,'application/json',JSON.stringify({status:'UNAVAILABLE',reason:'VIEW_SOURCE_UNAVAILABLE'})); }
});
server.requestTimeout=5000; server.headersTimeout=5000;
server.listen(17862,'127.0.0.1',()=>console.log(`${new Date().toISOString()} http://127.0.0.1:17862`));
server.on('error',e=>{console.error(e.code);process.exit(1);});
for (const signal of ['SIGTERM','SIGINT']) process.on(signal,()=>{server.close(()=>process.exit(0));setTimeout(()=>process.exit(1),2000).unref();});
