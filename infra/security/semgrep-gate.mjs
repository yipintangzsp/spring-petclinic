import fs from 'node:fs';
import {classifySemgrep,enforcedRules} from './semgrep-policy.mjs';
import {withScanner,transfer} from './scanner-runtime.mjs';

await withScanner('semgrep',['semgrep'],async({exec,report,pod,namespace})=>{
 exec(['mkdir','-p','/work/source','/work/positive','/work/negative','/work/command-positive','/work/command-negative']);
 // Only tracked application source from this exact commit; no credentials or full workspace.
 const {spawn}=await import('node:child_process');
 const archive=spawn('git',['archive','HEAD','src/main/java'],{stdio:['ignore','pipe','pipe']});
 const sink=spawn('kubectl',['--request-timeout=120s','-n',namespace,'exec','-i',pod,'--','tar','xf','-','-C','/work/source'],{stdio:['pipe','ignore','pipe']});
 archive.stdout.pipe(sink.stdin);sink.stdin.on('error',()=>{});
 const timer=setTimeout(()=>{archive.kill();sink.kill();},60000);
 try{await Promise.all([archive,sink].map(p=>new Promise((resolve,reject)=>{p.once('error',reject);p.once('close',c=>c===0?resolve():reject(Error('Exact-source transfer failed')));})) );}finally{clearTimeout(timer);}
 exec(['sh','-c','cat > /work/rules.json'],fs.readFileSync('infra/security/scan-rules.json'));
 exec(['sh','-c','cat > /work/positive/Unsafe.java'],'import javax.crypto.Cipher; class Unsafe { void run(String input) throws Exception { Runtime.getRuntime().exec(input); Cipher.getInstance("DES"); } }');
 exec(['sh','-c','cat > /work/negative/Safe.java'],'class Safe { void run() { System.out.println("synthetic"); } }');
 exec(['sh','-c','cat > /work/command-positive/HttpCommands.java'],'import jakarta.servlet.http.HttpServletRequest; class HttpCommands { void bad(HttpServletRequest req) throws Exception { String cmd=req.getParameter("cmd"); Runtime.getRuntime().exec(cmd); new ProcessBuilder(cmd).start(); } }');
 exec(['sh','-c','cat > /work/command-negative/FixedCommands.java'],'class FixedCommands { void safe() throws Exception { Runtime.getRuntime().exec("date"); new ProcessBuilder("java", "-version").start(); } }');
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
 report.fixtureResults={positive:positive.results,negative:negative.results,repeat:repeat.results};
 if(positive.results.length!==2||negative.results.length!==0||repeat.results.length!==2)throw Error('Semgrep detection/allow/repeat contract failed');
 const fixture=classifySemgrep(positive.results);if(fixture.blocking.length!==1||fixture.warnings.length!==1)throw Error('Semgrep FAIL/WARN fixture classification failed');
 report.tests={positive:2,negative:0,repeat:2,highConfidenceRejected:1,ordinaryWarn:1};
 const cp=scan('/work/command-positive'),cn=scan('/work/command-negative'),cr=scan('/work/command-positive');
 const ids=xs=>xs.filter(x=>['java-http-runtime-exec','java-http-process-builder'].includes(x.check_id));
 report.commandTests={positive:cp.results,negative:cn.results,repeat:cr.results,scope:'HTTP getParameter intraprocedural flow to entire executable; environment, shell arguments and wrappers remain WARN'};
 if(ids(cp.results).length!==2||cn.results.length!==0||ids(cr.results).length!==2)throw Error('HTTP command taint positive/negative/repeat contract failed');

 const result=scan('/work/source/src/main/java');report.sourceScan={findings:result.results,filesScanned:result.filesScanned,errors:result.errors};
 report.findingMode=process.env.GATE_SEMGREP??'enforce';
 if(!['warn','enforce'].includes(report.findingMode))throw Error('Invalid Semgrep finding mode');
 const classification=classifySemgrep(result.results);report.enforcedRules=enforcedRules;report.blockingFindings=classification.blocking;report.warningFindings=classification.warnings;report.warnings=classification.warnings.length?['Unreviewed or lower-severity SAST findings require review']:[];
 if(classification.blocking.length)throw Error('Reviewed high-confidence SAST findings: '+classification.blocking.length);
 report.rules=JSON.parse(fs.readFileSync('infra/security/scan-rules.json')).rules.map(x=>x.id);
 report.engine='Semgrep CE 1.182.1 native core; project-specific Java rules, not a full SAST guarantee';
});
