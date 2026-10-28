import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {withScanner,read,run} from './scanner-runtime.mjs';
import {highAlerts} from './gate-contract.mjs';

await withScanner('zap',['zap'],async({exec,report})=>{
 const temp=fs.mkdtempSync(path.join(os.tmpdir(),'zap-fixture-'));
 try{
  fs.writeFileSync(temp+'/Synthetic.java',`import com.sun.net.httpserver.HttpServer;import java.net.InetSocketAddress;public class Synthetic{public static void main(String[]a)throws Exception{var s=HttpServer.create(new InetSocketAddress("127.0.0.1",18083),0);s.createContext("/",e->{byte[]b="<html><head><title>Synthetic test</title></head><body>Test credit card: 4111 1111 1111 1111</body></html>".getBytes();e.getResponseHeaders().set("Content-Type","text/html");e.sendResponseHeaders(200,b.length);e.getResponseBody().write(b);e.close();});s.start();}}`);
  run('javac',['--release','21',temp+'/Synthetic.java']);
  exec(['mkdir','-p','/work/fixture']);exec(['sh','-c','cat > /work/fixture/Synthetic.class'],fs.readFileSync(temp+'/Synthetic.class'));
  exec(['sh','-c','java -Xmx32m -cp /work/fixture Synthetic >/work/fixture-server.log 2>&1 </dev/null & echo $! >/work/fixture.pid']);
  for(let i=0;i<20;i++){if(exec(['timeout','1','bash','-c','echo >/dev/tcp/127.0.0.1/18083'],undefined,[0,1,124]).status===0)break;if(i===19)throw Error('Loopback fixture did not start');await new Promise(r=>setTimeout(r,500));}
  const scan=(label,urls)=>{
   const plan={env:{contexts:[{name:label,urls}],parameters:{failOnError:true,failOnWarning:false}},jobs:[{type:'requestor',requests:urls.map(url=>({url,method:'GET',responseCode:200}))},{type:'passiveScan-wait',parameters:{maxDuration:1}},{type:'report',parameters:{template:'traditional-json',reportDir:'/work',reportFile:label,displayReport:false}}]};
   exec(['sh','-c',`cat > /work/${label}.yaml`],JSON.stringify(plan));
   const result=exec(['java','-Xmx384m','-Djava.awt.headless=true','-Djava.util.prefs.userRoot=/work/prefs','-jar','/work/tools/zap/zap-2.17.0.jar','-cmd','-silent','-host','127.0.0.1','-port','18084','-dir','/work/'+label+'-home','-autorun','/work/'+label+'.yaml'],undefined,[0],150000);
   fs.writeFileSync('.devsecops/zap-'+label+'.log',String(result.stdout)+String(result.stderr));
   const data=JSON.parse(String(exec(['cat','/work/'+label+'.json']).stdout));
   if(data.site.some(s=>!urls.some(url=>new URL(url).hostname===s['@host'])))throw Error('DAST visited a non-whitelisted target');
   return data;
  };
  const positive=scan('fixture',['http://127.0.0.1:18083/']);
  const found=highAlerts(positive);if(!found.length)throw Error('High-severity synthetic PII finding was not detected; gate negative case unproven');
  report.tests={syntheticHighDetected:found.map(a=>({pluginid:a.pluginid,riskcode:a.riskcode})),highFindingRejected:true};
  fs.writeFileSync('.devsecops/zap-fixture-report.json',JSON.stringify(positive,null,2));
  exec(['sh','-c','kill "$(cat /work/fixture.pid)"']);
  const deployment=read(['-n','petclinic','get','deploy','petclinic']);
  if(process.env.K8S_IMAGE&&deployment.spec.template.spec.containers[0].image!==process.env.K8S_IMAGE)throw Error('DAST target is not the promoted release');
  const service=read(['-n','petclinic','get','service','petclinic']);
  const base='http://'+service.spec.clusterIP+':'+service.spec.ports[0].port;
  const urls=['/','/owners/find','/vets.html','/actuator/health'].map(p=>base+p);
  const result=scan('business',urls);const blocking=highAlerts(result);
  report.targetImage=deployment.spec.template.spec.containers[0].image;report.targetUrls=urls;report.method='GET only; no spider, forms, or activeScan';
  report.findingMode=process.env.GATE_ZAP??'enforce';
  if(!['warn','enforce'].includes(report.findingMode))throw Error('Invalid ZAP finding mode');
  report.blockingHigh=blocking.length;report.findings=result.site.flatMap(s=>(s.alerts??[]).map(a=>({pluginid:a.pluginid,name:a.name,riskcode:a.riskcode,count:a.count})));
  report.warnings=report.findings.some(x=>Number(x.riskcode)<3)&&report.findingMode==='warn'?['Non-high passive DAST findings require review']:[];
  fs.writeFileSync('.devsecops/zap-business-report.json',JSON.stringify(result,null,2));
  if(blocking.length)throw Error('DAST blocked '+blocking.length+' high-severity findings');
 }finally{fs.rmSync(temp,{recursive:true,force:true});}
});
