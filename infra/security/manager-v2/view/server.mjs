import {startCIIntake} from './ci-intake.mjs';
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import {root} from './data.mjs';
import {sbomProjects} from '../sbom-real.mjs';
import {randomBytes,timingSafeEqual} from 'node:crypto';
import {overview} from './data.mjs';
import {capabilities,submit,getRun,recentRuns,updateControls} from './actions.mjs';
import {currentControls,projectControls,writeProjectControls} from './controls.mjs';
import {projectAccess,canReadRun} from './project-access.mjs';
import {localHost,localOrigin} from './origins.mjs';
const ciIntake=startCIIntake();
const csrf=randomBytes(32).toString('hex');
const access=projectAccess();
const authorized=access.authorized;
const instance = process.env.SECURITY_VIEW_INSTANCE ?? 'foreground';
const assets = new Map([['/', ['index.html','text/html; charset=utf-8']], ['/app.js',['app.js','text/javascript; charset=utf-8']], ['/style.css',['style.css','text/css; charset=utf-8']], ['/candidate-dashboard.json',['../observability/dashboard.json','application/json; charset=utf-8']]]);
const server = http.createServer(async(req,res) => {
  const headers = {'Cache-Control':'no-store','X-Content-Type-Options':'nosniff',
    'Content-Security-Policy':"default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
    'Referrer-Policy':'no-referrer'};
  const send=(code,type,body)=>{res.writeHead(code,{...headers,'Content-Type':type});res.end(req.method==='HEAD'?'':body);};
  if (!localHost(req.headers.host)) return send(403,'text/plain','Local host required');
  if (!['GET','HEAD','POST'].includes(req.method)) return send(405,'text/plain','Method not allowed');
  if (req.headers.origin && !localOrigin(req.headers.origin)) return send(403,'text/plain','Origin rejected');
  try {
    const url = new URL(req.url,'http://127.0.0.1:17862');
    const json=(code,v)=>send(code,'application/json',JSON.stringify(v));
    if(req.headers['sec-fetch-site']&& !['same-origin','none'].includes(req.headers['sec-fetch-site']))return json(403,{error:'CROSS_SITE_REJECTED'});
    if(req.method==='POST'){
      if(!['/api/run','/api/config','/api/config/reset','/api/sbom/operator-ticket'].includes(url.pathname)&&!/^\/api\/projects\/[A-Za-z0-9_.-]+\/config$/.test(url.pathname))return json(405,{error:'READ_ONLY_ROUTE'});
      const token=req.headers['x-csrf-token'];
      if(req.headers.origin!=='http://'+req.headers.host||typeof token!=='string'||token.length!==csrf.length||!timingSafeEqual(Buffer.from(token),Buffer.from(csrf)))return json(403,{error:'LOCAL_SESSION_REQUIRED'});
      if(req.headers['content-type']!=='application/json')return json(415,{error:'JSON_REQUIRED'});
      if(Number(req.headers['content-length'])>1024)return json(413,{error:'BODY_TOO_LARGE'});
      let bytes=0;const chunks=[];
      for await(const c of req){bytes+=c.length;if(bytes>1024){json(413,{error:'BODY_TOO_LARGE'});return;}chunks.push(c);}
      let value;try{value=JSON.parse(Buffer.concat(chunks).toString('utf8'));}catch{return json(400,{error:'INVALID_JSON'});}
      if(url.pathname==='/api/sbom/operator-ticket'){if(Object.keys(value).length)return json(400,{error:'INVALID_TICKET_REQUEST'});const ticket=access.ticket(req);return ticket?json(200,{ticket,expiresInSeconds:30}):json(403,{error:'LOCAL_OPERATOR_REQUIRED'});}
      const projectConfig=url.pathname.match(/^\/api\/projects\/([A-Za-z0-9_.-]+)\/config$/);
      if(projectConfig){if(!authorized(req,projectConfig[1]))return json(403,{error:'PROJECT_NOT_AUTHORIZED'});return json(200,writeProjectControls(projectConfig[1],value));}
      if(['/api/config','/api/config/reset'].includes(url.pathname)&&!access.operator(req))return json(403,{error:'LOCAL_OPERATOR_REQUIRED'});
      if(url.pathname==='/api/config')return json(200,updateControls(value));
      if(url.pathname==='/api/config/reset')return json(200,updateControls(value,true));
      if(value.pluginId==='sbom'&&!authorized(req,value.projectId))return json(403,{error:'PROJECT_NOT_AUTHORIZED'});
      return json(202,submit(value));
    }
    if(url.pathname==='/operator-login'){const cookie=access.consume(url.searchParams.get('ticket'));if(!cookie)return json(403,{error:'INVALID_OR_EXPIRED_LOCAL_TICKET'});res.writeHead(303,{...headers,'Set-Cookie':cookie,Location:'/#candidate-overview'});return res.end();}
    if(url.pathname==='/api/config'){if(!access.operator(req))return json(403,{error:'LOCAL_OPERATOR_REQUIRED'});return json(200,currentControls());}
    if(url.pathname==='/api/plugins')return json(200,{...capabilities(access.project(req)),csrfToken:csrf});
    if(url.pathname==='/api/sbom/projects')return json(200,{projects:Object.entries(sbomProjects()).map(([projectId,p])=>({projectId,displayName:p.displayName}))});
    if(url.pathname==='/api/sbom/session'){const projects=access.sessions(req);return projects?json(200,{projects}):json(403,{error:'LOCAL_OPERATOR_OR_PROJECT_IDENTITY_REQUIRED'});}
    if(url.pathname==='/api/runs')return json(200,{runs:recentRuns().filter(r=>canReadRun(req,r,access)).slice(0,20)});
    const configMatch=url.pathname.match(/^\/api\/projects\/([A-Za-z0-9_.-]+)\/config$/);
    if(configMatch){if(!authorized(req,configMatch[1]))return json(403,{error:'PROJECT_NOT_AUTHORIZED'});return json(200,projectControls(configMatch[1]));}
    if(url.pathname.startsWith('/api/projects/')){
      const m=url.pathname.match(/^\/api\/projects\/([a-zA-Z0-9_.-]+)\/runs\/(web-[a-f0-9-]{36})\/sbom$/);
      if(!m||!authorized(req,m[1]))return json(403,{error:'PROJECT_NOT_AUTHORIZED'});
      const r=getRun(m[2]);if(r.pluginId!=='sbom'||r.projectId!==m[1])return json(403,{error:'PROJECT_NOT_AUTHORIZED'});
      if(r.state!=='COMPLETED')return json(409,{error:'SBOM_NOT_AVAILABLE'});
      return send(200,'application/json',fs.readFileSync(path.join(root,'.devsecops/security-view-runs-v1',r.runId,'artifact/sbom.raw.json')));
    }
    if(url.pathname.startsWith('/api/runs/')){const r=getRun(url.pathname.slice('/api/runs/'.length));if(!canReadRun(req,r,access))return json(403,{error:'PROJECT_NOT_AUTHORIZED'});return json(200,r);}
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
for (const signal of ['SIGTERM','SIGINT']) process.on(signal,()=>{ciIntake?.server.close();if(ciIntake&&fs.existsSync(ciIntake.socket))fs.unlinkSync(ciIntake.socket);server.close(()=>process.exit(0));setTimeout(()=>process.exit(1),2000).unref();});
