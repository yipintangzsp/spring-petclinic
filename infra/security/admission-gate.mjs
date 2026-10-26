import fs from 'node:fs';
import {spawnSync} from 'node:child_process';
const namespace='devsecops-execution', tool=JSON.parse(fs.readFileSync('infra/security/tools-lock.json')).gitleaks;
const pod={apiVersion:'v1',kind:'Pod',metadata:{name:'devsecops-contract-probe',namespace},spec:{automountServiceAccountToken:false,restartPolicy:'Never',securityContext:{runAsNonRoot:true,runAsUser:65532,seccompProfile:{type:'RuntimeDefault'}},containers:[{name:'probe',image:tool.image,command:['gitleaks','version'],securityContext:{allowPrivilegeEscalation:false,readOnlyRootFilesystem:true,capabilities:{drop:['ALL']}},resources:{requests:{cpu:'100m',memory:'256Mi'},limits:{cpu:'1',memory:'512Mi'}}}]}};
const evidence={startedAt:new Date().toISOString(),cases:[],status:'failed'};
function probe(spec,denied){
 const r=spawnSync('kubectl',['--request-timeout=20s','create','--dry-run=server','-f','-','-o','json'],{input:JSON.stringify(spec),encoding:'utf8',timeout:25000,maxBuffer:1024*1024});
 if(r.error)throw r.error;
 if(denied ? r.status===0||!/devsecops-workload-contract/.test(r.stderr) : r.status!==0)throw Error('Admission mismatch: '+r.stderr.slice(-1500));
 return {allowed:r.status===0,diagnostic:denied?r.stderr.slice(-1800):'server dry-run accepted; no Pod created'};
}
try{
 evidence.cases.push({case:'compliant-pod',...probe(pod,false)});
 const mutations={mutable_image:p=>p.spec.containers[0].image='alpine:latest',host_network:p=>p.spec.hostNetwork=true,host_path:p=>p.spec.volumes=[{name:'escape',hostPath:{path:'/etc'}}],privileged:p=>{p.spec.containers[0].securityContext.privileged=true;p.spec.containers[0].securityContext.allowPrivilegeEscalation=true;delete p.spec.securityContext.seccompProfile;},missing_limits:p=>delete p.spec.containers[0].resources.limits,token_mount:p=>p.spec.automountServiceAccountToken=true,root_identity:p=>p.spec.securityContext.runAsNonRoot=false};
 for(const [name,change] of Object.entries(mutations)){const p=structuredClone(pod);change(p);evidence.cases.push({case:name,...probe(p,true)});}
 evidence.status='success';
}finally{fs.mkdirSync('.devsecops',{recursive:true});fs.writeFileSync('.devsecops/admission-gate.json',JSON.stringify(evidence,null,2));}
console.log('Kyverno actual server dry-run: compliant accepted; seven violations denied');
