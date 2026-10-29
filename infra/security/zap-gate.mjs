import fs from 'node:fs';
import crypto from 'node:crypto';
import {classifyZap} from './zap-policy.mjs';
import os from 'node:os';
import path from 'node:path';
import {withScanner,read,run} from './scanner-runtime.mjs';
import {highAlerts} from './gate-contract.mjs';

await withScanner('zap',['zap'],async({exec,report})=>{
 const temp=fs.mkdtempSync(path.join(os.tmpdir(),'zap-fixture-'));
 try{
  fs.writeFileSync(temp+'/Synthetic.java',`import com.sun.net.httpserver.HttpServer;import java.net.InetSocketAddress;public class Synthetic{public static void main(String[]a)throws Exception{var s=HttpServer.create(new InetSocketAddress("127.0.0.1",18083),0);s.createContext("/",e->{byte[]b=(e.getRequestURI().getPath().equals("/clean")?"<html><head><title>Clean synthetic test</title></head><body>Fixed public fixture</body></html>":"<html><head><title>Synthetic test</title></head><body>Test credit card: 4111 1111 1111 1111</body></html>").getBytes();e.getResponseHeaders().set("Content-Type","text/html");e.sendResponseHeaders(200,b.length);e.getResponseBody().write(b);e.close();});for(String path:new String[]{"/protected","/admin","/owned/alice"}){s.createContext(path,e->{String token=e.getRequestHeaders().getFirst("Authorization");boolean admin="Bearer fixture-admin".equals(token),alice="Bearer fixture-alice".equals(token),bob="Bearer fixture-bob".equals(token);String route=e.getHttpContext().getPath();boolean expired="Bearer fixture-expired".equals(token)&&System.currentTimeMillis()>=946684800000L;int status=expired||!(admin||alice||bob)?401:route.equals("/admin")&&!admin?403:route.equals("/owned/alice")&&!(admin||alice)?403:200;byte[]body=("fixture-status-"+status).getBytes();e.getResponseHeaders().set("Content-Type","text/plain");e.sendResponseHeaders(status,body.length);e.getResponseBody().write(body);e.close();});}s.createContext("/broken-protected",e->{byte[]body="intentional fixture authorization bypass".getBytes();e.sendResponseHeaders(200,body.length);e.getResponseBody().write(body);e.close();});s.start();}}`);
  fs.copyFileSync('infra/security/ZapAuthProbe.java',temp+'/ZapAuthProbe.java');
  run('javac',['--release','21',temp+'/Synthetic.java',temp+'/ZapAuthProbe.java']);
  exec(['mkdir','-p','/work/fixture']);exec(['sh','-c','cat > /work/fixture/Synthetic.class'],fs.readFileSync(temp+'/Synthetic.class'));
  exec(['sh','-c','java -Xmx32m -cp /work/fixture Synthetic >/work/fixture-server.log 2>&1 </dev/null & echo $! >/work/fixture.pid']);
  for(let i=0;i<20;i++){if(exec(['timeout','1','bash','-c','echo >/dev/tcp/127.0.0.1/18083'],undefined,[0,1,124]).status===0)break;if(i===19)throw Error('Loopback fixture did not start');await new Promise(r=>setTimeout(r,500));}
  const scan=(label,urls)=>{
   if(!['fixture','fixture-negative','business'].includes(label))throw Error('Only owned ZAP scratch labels allowed');
   const plan={env:{contexts:[{name:label,urls}],parameters:{failOnError:true,failOnWarning:false}},jobs:[{type:'requestor',requests:urls.map(url=>({url,method:'GET',responseCode:200}))},{type:'passiveScan-wait',parameters:{maxDuration:1}},{type:'report',parameters:{template:'traditional-json',reportDir:'/work',reportFile:label,displayReport:false}},...(label==='business'?[{type:'report',parameters:{template:'traditional-xml',reportDir:'/work',reportFile:label,displayReport:false}}]:[])]};
   exec(['sh','-c',`cat > /work/${label}.yaml`],JSON.stringify(plan));
   const result=exec(['java','-Xmx384m','-Djava.awt.headless=true','-Djava.util.prefs.userRoot=/work/prefs','-jar','/work/tools/zap/zap-2.17.0.jar','-cmd','-silent','-host','127.0.0.1','-port','18084','-dir','/work/'+label+'-home','-autorun','/work/'+label+'.yaml'],undefined,[0],150000);
   fs.writeFileSync('.devsecops/zap-'+label+'.log',String(result.stdout)+String(result.stderr));
   const data=JSON.parse(String(exec(['cat','/work/'+label+'.json']).stdout));
   if(label==='business')fs.writeFileSync('.devsecops/zap-business-report.xml',String(exec(['cat','/work/'+label+'.xml']).stdout));
   if(data.site.some(s=>!urls.some(url=>new URL(url).hostname===s['@host'])))throw Error('DAST visited a non-whitelisted target');
   if(process.env.SECURITY_CLEANUP_SCAN_HOMES==='true'){
    const native='.devsecops/zap-'+label+'-native.json';fs.writeFileSync(native,JSON.stringify(data,null,2));
    fs.writeFileSync('.devsecops/zap-'+label+'-plan.json',JSON.stringify(plan,null,2));
    const home='/work/'+label+'-home';const before=String(exec(['du','-sk',home]).stdout).trim();
    // The synchronous JVM has exited; native reports, plans and stdout/stderr are retained above.
    exec(['rm','-rf','--',home]);
    report.sessionCleanup??=[];report.sessionCleanup.push({label,jvmExited:true,nativeReport:native,reportSha256:crypto.createHash('sha256').update(fs.readFileSync(native)).digest('hex'),scratchBefore:before,removedHome:home});
   }
   return data;
  };
  const positive=scan('fixture',['http://127.0.0.1:18083/']);
  const found=highAlerts(positive);if(!found.length)throw Error('High-severity synthetic PII finding was not detected; gate negative case unproven');
  const approved=JSON.parse(fs.readFileSync('infra/security/zap-confirmations.json'));
  for(const proof of approved.confirmations??[]){
   proof.evidenceVerified=false;
   if(!/^infra\/security\/dast-evidence\/[a-zA-Z0-9_-]+\.json$/.test(proof.evidencePath??''))throw Error('DAST proof must reference a reviewed evidence file');
   const bytes=fs.readFileSync(proof.evidencePath);if(crypto.createHash('sha256').update(bytes).digest('hex')!==proof.evidenceSha256)throw Error('DAST evidence digest mismatch');
   const evidence=JSON.parse(bytes);if(!['pluginid','targetImage','reportSha256','uri','category'].every(k=>evidence[k]===proof[k])||evidence.positiveValidated!==true||evidence.negativeValidated!==true||evidence.exploitConfirmed!==true)throw Error('DAST exploit evidence binding invalid');
   proof.evidenceVerified=true;
  }

  const fixtureGate=classifyZap(positive,{targetImage:'loopback-fixture',reportSha256:'synthetic-fixture'},approved);
  if(fixtureGate.blocking.length||fixtureGate.unconfirmedHigh<1)throw Error('Unconfirmed synthetic information finding must remain WARN');
  const clean=scan('fixture-negative',['http://127.0.0.1:18083/clean']);
  if(highAlerts(clean).some(x=>String(x.pluginid)==='10062'))throw Error('Clean fixture triggered synthetic PII false positive');
  fs.writeFileSync('.devsecops/zap-fixture-negative-report.json',JSON.stringify(clean,null,2));
  report.tests={syntheticHighDetected:found.map(a=>({pluginid:a.pluginid,riskcode:a.riskcode})),unconfirmedInformationHighWarn:true,cleanFixtureNoPiiHigh:true,exploitValidationNotClaimed:true};
  fs.writeFileSync('.devsecops/zap-fixture-report.json',JSON.stringify(positive,null,2));
  const authDeployment=read(['-n','petclinic','get','deploy','petclinic']);const authService=read(['-n','petclinic','get','service','petclinic']);
  const authBase='http'+ '://'+authService.spec.clusterIP+':'+authService.spec.ports[0].port;
  exec(['sh','-c','cat > /work/fixture/ZapAuthProbe.class'],fs.readFileSync(temp+'/ZapAuthProbe.class'));
  const authEvidence=JSON.parse(String(exec(['java','-Xmx32m','-cp','/work/fixture','ZapAuthProbe',authBase],undefined,[0],240000).stdout));
  authEvidence.targetImage=authDeployment.spec.template.spec.containers[0].image;authEvidence.bodyContentSaved=false;
  fs.writeFileSync('.devsecops/zap-auth-readonly.json',JSON.stringify(authEvidence,null,2));
  report.authentication={status:'WARN-production-identity-model-unavailable',fixtureCases:authEvidence.fixture.length,publicGetObservations:authEvidence.business.length,unsupported:authEvidence.productionUnsupported,scope:authEvidence.businessScope};
  exec(['sh','-c','kill "$(cat /work/fixture.pid)"']);
  const deployment=read(['-n','petclinic','get','deploy','petclinic']);
  if(process.env.K8S_IMAGE&&deployment.spec.template.spec.containers[0].image!==process.env.K8S_IMAGE)throw Error('DAST target is not the promoted release');
  const service=read(['-n','petclinic','get','service','petclinic']);
  const base='http://'+service.spec.clusterIP+':'+service.spec.ports[0].port;
  const urls=['/','/owners/find','/vets.html','/actuator/health'].map(p=>base+p);
  const result=scan('business',urls);const reportSha256=crypto.createHash('sha256').update(JSON.stringify(result)).digest('hex');const classification=classifyZap(result,{targetImage:deployment.spec.template.spec.containers[0].image,reportSha256},approved);const blocking=classification.blocking;
  report.targetImage=deployment.spec.template.spec.containers[0].image;report.targetUrls=urls;report.method='GET only; no spider, forms, or activeScan';
  report.findingMode=process.env.GATE_ZAP??'enforce';
  if(!['warn','enforce'].includes(report.findingMode))throw Error('Invalid ZAP finding mode');
  report.reportSha256=reportSha256;report.rawHigh=classification.rawHigh;report.unconfirmedHigh=classification.unconfirmedHigh;report.confirmedHigh=blocking;report.coverage={sqlInjection:'not confirmed by passive GET',commandInjection:'not confirmed by passive GET',xss:'not confirmed exploitable',pathTraversal:'not confirmed by passive GET',ssrf:'not confirmed by passive GET',authBypass:'public GET credential observations and isolated role fixtures; real production identity model unavailable; exploit not confirmed'};report.blockingHigh=blocking.length;report.findings=result.site.flatMap(s=>(s.alerts??[]).map(a=>({pluginid:a.pluginid,name:a.name,riskcode:a.riskcode,count:a.count})));
  report.warningFindings=classification.warnings.map(x=>({pluginid:x.pluginid,riskcode:x.riskcode,reason:x.gateReason}));report.warnings=[...(classification.warnings.length?['Unconfirmed High and ordinary passive DAST findings remain WARN']:[]),'Production user/admin/ownership differential unavailable; synthetic evidence is not production authorization proof'];
  fs.writeFileSync('.devsecops/zap-business-report.json',JSON.stringify(result,null,2));
  if(blocking.length)throw Error('DAST blocked '+blocking.length+' high-severity findings');
 }finally{fs.rmSync(temp,{recursive:true,force:true});}
});
