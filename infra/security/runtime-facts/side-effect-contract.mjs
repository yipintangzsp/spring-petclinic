// Dedicated validation authorization, never imported by production stages.
import fs from 'node:fs';import path from 'node:path';import {fail} from '../summary-v2/codec.mjs';
export function validateContract(c){
 if(c?.schema!==1||!/^rfv-\d{8}-[a-f0-9]{6}$/.test(c.validationRunId)||!['gitleaks','semgrep-command-audit'].includes(c.sourceId)||!Number.isSafeInteger(c.build)||!c.kubeconfig?.startsWith('/tmp/runtime-six-')||!c.workspace?.startsWith('/tmp/runtime-six-')||!c.realKubectl?.startsWith('/')||c.server!=='https://kubernetes.default.svc'||c.namespace!=='devsecops-execution'||!c.allowedImages?.every(x=>x.includes('@sha256:'))||!c.allowedImages.length||c.release!==false||c.rollout!==false)fail('Invalid controlled side-effect contract');return c;
}
export function authorizeKubectl(argv,input,c,ledger){
 validateContract(c);const a=argv.filter(x=>!/^--request-timeout=/.test(x));
 if(a[0]==='create'&&JSON.stringify(a)===JSON.stringify(['create','-f','-','-o','json'])){
  let p;try{p=JSON.parse(input);}catch{fail('Invalid validation Pod');}
  const prefix=c.sourceId==='gitleaks'?'source-'+c.build+'-':'semgrep-'+c.build+'-';
  const name=p?.metadata?.name;const match=(c.sourceId==='semgrep-command-audit'&&name==='command-audit-'+c.build)||name?.startsWith(prefix);
  if(p.kind!=='Pod'||p.apiVersion!=='v1'||p.metadata.namespace!==c.namespace||!match||ledger.some(o=>o.name===name)||p.spec?.automountServiceAccountToken!==false||p.spec?.restartPolicy!=='Never'||!p.spec.activeDeadlineSeconds||p.spec.activeDeadlineSeconds>600||p.spec.hostNetwork||p.spec.hostPID||p.spec.hostIPC||p.spec.serviceAccountName||p.spec.volumes?.some(v=>!v.emptyDir)||!p.spec.securityContext?.runAsNonRoot||!p.spec.containers?.length||p.spec.containers.some(x=>!c.allowedImages.includes(x.image)||x.securityContext?.allowPrivilegeEscalation!==false||!x.securityContext?.readOnlyRootFilesystem||JSON.stringify(x.securityContext?.capabilities?.drop)!=='["ALL"]'||x.securityContext?.privileged))fail('Pod outside controlled validation identity/security boundary');
  return {action:'create',name};
 }
 if(a[0]==='-n'&&a[1]==='data-infra'&&JSON.stringify(a.slice(2))===JSON.stringify(['get','lease','platform-heavy','-o','json']))return {action:'read-lease'};
 if(a[0]==='-n'&&a[1]===c.namespace){
  const b=a.slice(2),name=b[2],owned=ledger.find(o=>o.name===name);
  if(b[0]==='get'&&b[1]==='pod'&&owned&&JSON.stringify(b.slice(3))==='["-o","json"]')return {action:'read-pod',name};
  if(b[0]==='get'&&b[1]==='pod'&&owned&&JSON.stringify(b.slice(3))==='["--ignore-not-found","-o","name"]')return {action:'verify-absent',name};
  if(b[0]==='exec'&&b[1]==='-i'&&ledger.some(o=>o.name===b[2])&&b[3]==='--')return {action:'exec',name:b[2]};
  if(b[0]==='wait'&&b[1]==='--for=condition=Ready'&&b[2]?.startsWith('pod/')&&ledger.some(o=>o.name===b[2].slice(4))&&/^--timeout=(90|180)s$/.test(b[3]??'')&&b.length===4)return {action:'wait',name:b[2].slice(4)};
  if(b[0]==='wait'&&b[1]==='--for=delete'&&ledger.some(o=>'pod/'+o.name===b[2])&&b[3]==='--timeout=60s'&&b.length===4)return {action:'verify-delete',name:b[2].slice(4)};
  if(b[0]==='delete'&&b[1]==='pod'&&owned&&JSON.stringify(b.slice(3))==='["--wait=true","--timeout=45s"]')return {action:'delete',name};
 }
 if(a[0]==='delete'&&a[1]==='--raw'&&a[3]==='-f'&&a[4]==='-'&&a.length===5){
  const o=ledger.find(o=>a[2]===`/api/v1/namespaces/${c.namespace}/pods/${o.name}`);let v;try{v=JSON.parse(input);}catch{}
  if(o&&v?.preconditions?.uid===o.uid)return {action:'delete',name:o.name};
 }
 fail('FORBIDDEN_RELEASE_OR_UNSCOPED_KUBERNETES_ACTION');
}
export function authorizeProcess(bin,args,c){
 const name=path.basename(String(bin));
 if(bin==='kubectl')return;
 if(name==='git'&&((args.length===2&&args[0]==='rev-parse'&&args[1]==='HEAD')||(args[0]==='archive'&&args.every(x=>['archive','--format=tar','HEAD','src/main/java'].includes(x)))||(JSON.stringify(args)===JSON.stringify(['ls-files','src/main','infra','Jenkinsfile','Jenkinsfile.security-audit']))))return;
 if(name==='tar'&&args[0]==='cf'&&args[1]==='-'&&args[2]==='-C'&&args[3]==='/var/jenkins_home/platform-security/20261027'&&args.slice(4).every(x=>x==='semgrep'))return;
 fail('FORBIDDEN_RELEASE_OR_UNSCOPED_PROCESS');
}
