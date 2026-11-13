import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {execFileSync,spawnSync} from 'node:child_process';

export function ownsStoppedTest(container, containersBefore, volumesBefore, workspace) {
 const labels=container.Config?.Labels??{};
 const volumes=(container.Mounts??[]).filter(m=>m.Type==='volume').map(m=>m.Name);
 return !containersBefore.has(container.Id)
  && labels['com.docker.compose.project']==='petclinic-ci'
  && labels['com.docker.compose.service']==='postgres'
  && path.resolve(labels['com.docker.compose.project.working_dir']??'/')===path.resolve(workspace)
  && container.State?.Running===false
  && volumes.every(name=>name&&!volumesBefore.has(name));
}

export function run() {
 const docker=(...args)=>execFileSync('docker',args,{encoding:'utf8',timeout:30000}).trim();
 const list=value=>value.split(/\s+/).filter(Boolean);
 const containersBefore=new Set(list(docker('ps','-aq','--no-trunc')));
 const volumesBefore=new Set(list(docker('volume','ls','-q')));
 const started=Date.now();
 const result=spawnSync('nice',['-n','10','./mvnw','-B','clean','test'],{stdio:'inherit'});
 const report={test_exit_code:result.status??1,removed:[],retained:[]};
 try {
  for(const id of list(docker('ps','-aq','--no-trunc'))) {
   if(containersBefore.has(id))continue;
   const container=JSON.parse(docker('inspect',id))[0];
   if(container.Config?.Labels?.['com.docker.compose.project']!=='petclinic-ci')continue;
   if(!ownsStoppedTest(container,containersBefore,volumesBefore,process.cwd())) {
    report.retained.push({id,reason:'ownership, lifecycle or pre-existing-volume guard'});continue;
   }
   docker('rm','--volumes',id);
   report.removed.push({id,anonymous_volumes:container.Mounts.filter(m=>m.Type==='volume').map(m=>m.Name)});
  }
 } finally {
  report.elapsed_seconds=(Date.now()-started)/1000;
  fs.mkdirSync('target/platform',{recursive:true});
  fs.writeFileSync('target/platform/integration-test-cleanup.json',JSON.stringify(report,null,2));
 }
 process.exitCode=report.test_exit_code;
}
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url))run();
