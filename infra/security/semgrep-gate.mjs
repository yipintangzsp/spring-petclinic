import fs from 'node:fs';
import {withScanner,transfer} from './scanner-runtime.mjs';

await withScanner('semgrep',['semgrep'],async({exec,report,pod,namespace})=>{
 exec(['mkdir','-p','/work/source','/work/positive','/work/negative']);
 // Only tracked application source from this exact commit; no credentials or full workspace.
 const {spawn}=await import('node:child_process');
 const archive=spawn('git',['archive','HEAD','src/main/java'],{stdio:['ignore','pipe','pipe']});
 const sink=spawn('kubectl',['--request-timeout=120s','-n',namespace,'exec','-i',pod,'--','tar','xf','-','-C','/work/source'],{stdio:['pipe','ignore','pipe']});
 archive.stdout.pipe(sink.stdin);sink.stdin.on('error',()=>{});
 const timer=setTimeout(()=>{archive.kill();sink.kill();},60000);
 try{await Promise.all([archive,sink].map(p=>new Promise((resolve,reject)=>{p.once('error',reject);p.once('close',c=>c===0?resolve():reject(Error('Exact-source transfer failed')));})) );}finally{clearTimeout(timer);}
 exec(['sh','-c','cat > /work/rules.json'],fs.readFileSync('infra/security/scan-rules.json'));
 exec(['sh','-c','cat > /work/positive/Unsafe.java'],'class Unsafe { void run(String input) throws Exception { Runtime.getRuntime().exec(input); } }');
 exec(['sh','-c','cat > /work/negative/Safe.java'],'class Safe { void run() { System.out.println("synthetic"); } }');
 const scan=path=>{
  const files=String(exec(['find',path,'-type','f','-name','*.java']).stdout).trim().split('\n').filter(Boolean).sort();
  if(!files.length||files.length>500)throw Error('Bounded nonempty Java source list required');
  const result={results:[],errors:[],filesScanned:files.length};
  for(const file of files){
   if(!file.startsWith(path+'/'))throw Error('Unexpected target path');
   const r=exec(['/work/tools/semgrep/semgrep-core','-rules','/work/rules.json','-lang','java','-json','-json_nodots','-j','1','-timeout','5','-max_memory','512',file],undefined,[0],30000);
   const d=JSON.parse(String(r.stdout));if(d.errors?.length)throw Error('Semgrep parse/scan errors are blocking');result.results.push(...d.results);
  }
  return result;
 };
 const positive=scan('/work/positive'),negative=scan('/work/negative'),repeat=scan('/work/positive');
 if(positive.results.length!==1||negative.results.length!==0||repeat.results.length!==1)throw Error('Semgrep detection/allow/repeat contract failed');
 report.tests={positive:1,negative:0,repeat:1};
 const result=scan('/work/source/src/main/java');report.sourceScan={findings:result.results,filesScanned:result.filesScanned,errors:result.errors};
 report.findingMode=process.env.GATE_SEMGREP??'enforce';
 if(!['warn','enforce'].includes(report.findingMode))throw Error('Invalid Semgrep finding mode');
 report.warnings=result.results.length&&report.findingMode==='warn'?['SAST application findings require review']:[];
 if(result.results.length&&report.findingMode==='enforce')throw Error('SAST gate blocked '+result.results.length+' application findings');
 report.rules=JSON.parse(fs.readFileSync('infra/security/scan-rules.json')).rules.map(x=>x.id);
 report.engine='Semgrep CE 1.182.1 native core; six project-specific Java rules, not a full SAST guarantee';
});
