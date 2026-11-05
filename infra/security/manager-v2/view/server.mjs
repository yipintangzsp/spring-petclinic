import http from 'node:http';
import fs from 'node:fs';
import {randomBytes,timingSafeEqual} from 'node:crypto';
import {overview} from './data.mjs';
import {capabilities,submit,getRun,recentRuns} from './actions.mjs';
const csrf=randomBytes(32).toString('hex');
const instance = process.env.SECURITY_VIEW_INSTANCE ?? 'foreground';
const assets = new Map([['/', ['index.html','text/html; charset=utf-8']], ['/app.js',['app.js','text/javascript; charset=utf-8']], ['/style.css',['style.css','text/css; charset=utf-8']]]);
const server = http.createServer(async(req,res) => {
  const headers = {'Cache-Control':'no-store','X-Content-Type-Options':'nosniff',
    'Content-Security-Policy':"default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
    'Referrer-Policy':'no-referrer'};
  const send=(code,type,body)=>{res.writeHead(code,{...headers,'Content-Type':type});res.end(req.method==='HEAD'?'':body);};
  if (!['127.0.0.1:17862','localhost:17862'].includes(req.headers.host)) return send(403,'text/plain','Local host required');
  if (!['GET','HEAD','POST'].includes(req.method)) return send(405,'text/plain','Method not allowed');
  if (req.headers.origin && !['http://127.0.0.1:17862','http://localhost:17862'].includes(req.headers.origin)) return send(403,'text/plain','Origin rejected');
  try {
    const url = new URL(req.url,'http://127.0.0.1:17862');
    const json=(code,v)=>send(code,'application/json',JSON.stringify(v));
    if(req.headers['sec-fetch-site']&& !['same-origin','none'].includes(req.headers['sec-fetch-site']))return json(403,{error:'CROSS_SITE_REJECTED'});
    if(req.method==='POST'){
      if(url.pathname!=='/api/run')return json(405,{error:'READ_ONLY_ROUTE'});
      const token=req.headers['x-csrf-token'];
      if(req.headers.origin!=='http://'+req.headers.host||typeof token!=='string'||token.length!==csrf.length||!timingSafeEqual(Buffer.from(token),Buffer.from(csrf)))return json(403,{error:'LOCAL_SESSION_REQUIRED'});
      if(req.headers['content-type']!=='application/json')return json(415,{error:'JSON_REQUIRED'});
      if(Number(req.headers['content-length'])>1024)return json(413,{error:'BODY_TOO_LARGE'});
      let bytes=0;const chunks=[];
      for await(const c of req){bytes+=c.length;if(bytes>1024){json(413,{error:'BODY_TOO_LARGE'});return;}chunks.push(c);}
      let value;try{value=JSON.parse(Buffer.concat(chunks).toString('utf8'));}catch{return json(400,{error:'INVALID_JSON'});}
      return json(202,submit(value));
    }
    if(url.pathname==='/api/plugins')return json(200,{...capabilities(),csrfToken:csrf});
    if(url.pathname==='/api/runs')return json(200,{runs:recentRuns()});
    if(url.pathname.startsWith('/api/runs/'))return json(200,getRun(url.pathname.slice('/api/runs/'.length)));
    if (url.pathname==='/api/health') return send(200,'application/json',JSON.stringify({service:'security-manager-v2-readonly',instance,pid:process.pid}));
    if (url.pathname==='/api/overview') return send(200,'application/json',JSON.stringify(overview()));
    const asset = assets.get(url.pathname);
    if (!asset) return send(404,'text/plain','Not found');
    send(200,asset[1],fs.readFileSync(new URL(asset[0],import.meta.url)));
  } catch(e) { send(e.status??503,'application/json',JSON.stringify({status:'UNAVAILABLE',reason:/^[A-Z_]+$/.test(e.code??'')?e.code:'VIEW_SOURCE_UNAVAILABLE'})); }
});
server.requestTimeout=5000; server.headersTimeout=5000;
server.listen(17862,'127.0.0.1',()=>console.log(`${new Date().toISOString()} http://127.0.0.1:17862`));
server.on('error',e=>{console.error(e.code);process.exit(1);});
for (const signal of ['SIGTERM','SIGINT']) process.on(signal,()=>{server.close(()=>process.exit(0));setTimeout(()=>process.exit(1),2000).unref();});
