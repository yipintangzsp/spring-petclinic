// OFFLINE REVIEW ONLY. No Kubernetes, Docker, Jenkins, network or provisioning client.
// This does not replace the sealed CI entry's host-systemd identity check.
import {resolveCI,AGENT,JOB,RELEASE} from '../../../security/manager-v2/ci/contract.mjs';
export {AGENT,JOB,RELEASE};
export const NS='devsecops-execution';
export const UID=24001; // Proposed only: inspected root-owned 0755 tools; no host account/process found.
export const SA='gitleaks-validation-agent';
export const UNRESOLVED_IMAGE='127.0.0.1:30050/platform-security/gitleaks-validation-agent@sha256:UNRESOLVED';
export const LABELS={'security.devops.local/purpose':'gitleaks-validation','security.devops.local/run-id':'REQUIRES_BOUND_RUN_ID'};
export const clone=x=>structuredClone(x);
const same=(a,b)=>JSON.stringify(a)===JSON.stringify(b);
const must=(x,message)=>{if(!x)throw Error('AGENT_PLAN_REJECTED: '+message);};
const security={allowPrivilegeEscalation:false,readOnlyRootFilesystem:true,privileged:false,capabilities:{drop:['ALL']},runAsNonRoot:true,runAsUser:UID,runAsGroup:UID,seccompProfile:{type:'RuntimeDefault'}};
export function candidateSA(){return {apiVersion:'v1',kind:'ServiceAccount',metadata:{name:SA,namespace:NS},automountServiceAccountToken:false};}
export function candidatePod(){return {
 apiVersion:'v1',kind:'Pod',metadata:{generateName:'gitleaks-v2-',namespace:NS,labels:clone(LABELS),annotations:{'security.devops.local/review-only':'true','security.devops.local/execution-readiness':'CI_EXECUTION_NOT_READY'}},
 spec:{serviceAccountName:SA,automountServiceAccountToken:false,enableServiceLinks:false,
 hostNetwork:false,hostPID:false,hostIPC:false,shareProcessNamespace:false,
 restartPolicy:'Never',activeDeadlineSeconds:600,terminationGracePeriodSeconds:30,preemptionPolicy:'Never',
 securityContext:{runAsNonRoot:true,runAsUser:UID,runAsGroup:UID,fsGroup:UID,supplementalGroups:[],supplementalGroupsPolicy:'Strict',fsGroupChangePolicy:'OnRootMismatch',seccompProfile:{type:'RuntimeDefault'}},
 affinity:{nodeAffinity:{requiredDuringSchedulingIgnoredDuringExecution:{nodeSelectorTerms:[{matchExpressions:[{key:'kubernetes.io/os',operator:'In',values:['linux']},{key:'kubernetes.io/arch',operator:'In',values:['arm64']}]}]}}},
 containers:[{name:'validation-agent',image:UNRESOLVED_IMAGE,imagePullPolicy:'Never',securityContext:clone(security),
 command:['/usr/bin/tini','-s','-g','--','/opt/java/openjdk/bin/java'],
 args:['-Xmx192m','-XX:MaxMetaspaceSize=96m','-XX:MaxDirectMemorySize=32m','-XX:ReservedCodeCacheSize=48m','-Djava.io.tmpdir=/tmp','-jar','/opt/agent/agent.jar','-url','http://jenkins.ns-devops.svc.cluster.local:8080/','-webSocket','-secret','@/agent-auth/secret','-name',AGENT,'-workDir','/work/remoting','-noReconnect'],
 env:[{name:'HOME',value:'/work/home'},{name:'TMPDIR',value:'/tmp'},{name:'JENKINS_HOME',value:'/work/home'},{name:'NODE_OPTIONS',value:'--max-old-space-size=128'},{name:'POD_UID',valueFrom:{fieldRef:{fieldPath:'metadata.uid'}}}],
 resources:{requests:{cpu:'250m',memory:'512Mi','ephemeral-storage':'128Mi'},limits:{cpu:'1',memory:'768Mi','ephemeral-storage':'256Mi'}},
 volumeMounts:[{name:'work',mountPath:'/work'},{name:'temp',mountPath:'/tmp'},{name:'agent-auth',mountPath:'/agent-auth',readOnly:true}]}],
 volumes:[{name:'work',emptyDir:{medium:'Memory',sizeLimit:'128Mi'}},{name:'temp',emptyDir:{medium:'Memory',sizeLimit:'32Mi'}},
 {name:'agent-auth',secret:{secretName:'gitleaks-v2-REQUIRES_BOUND_RUN_ID',defaultMode:0o440,items:[{key:'secret',path:'secret'}]}}]
 }};}
export function candidateNetworkPolicy(){return {
 apiVersion:'networking.k8s.io/v1',kind:'NetworkPolicy',metadata:{name:'gitleaks-agent-controller-only',namespace:NS},spec:{
 podSelector:{matchLabels:{'security.devops.local/purpose':'gitleaks-validation'}},policyTypes:['Ingress','Egress'],ingress:[],
 egress:[{to:[{namespaceSelector:{matchLabels:{'kubernetes.io/metadata.name':'ns-devops'}},podSelector:{matchLabels:{app:'jenkins'}}}],ports:[{protocol:'TCP',port:8080}]},
 {to:[{namespaceSelector:{matchLabels:{'kubernetes.io/metadata.name':'kube-system'}},podSelector:{matchLabels:{'k8s-app':'kube-dns'}}}],ports:[{protocol:'UDP',port:53},{protocol:'TCP',port:53}]}]
 }};}
export const readinessKeys=['AGENT_CAPABILITY_READY','AGENT_IDENTITY_READY','AGENT_RESOURCE_READY','AGENT_NETWORK_READY','AGENT_IMAGE_READY','AGENT_CLEANUP_READY','AGENT_JOB_BINDING_READY'];
export function assertReadiness(r){
 must(r&&same(Object.keys(r).sort(),[...readinessKeys].sort()),'readiness keys must be explicit and exact');
 for(const k of readinessKeys)must(r[k]===true,'unproven '+k);
 return true;
}
export function validateCandidate({pod,sa,networkPolicy},{reviewOnly=false,approvedImage=null}={}){
 must(pod?.kind==='Pod'&&sa?.kind==='ServiceAccount'&&networkPolicy?.kind==='NetworkPolicy','resource kinds');
 must(pod.metadata.namespace===NS&&sa.metadata.namespace===NS&&networkPolicy.metadata.namespace===NS,'namespace');
 must(same(sa,candidateSA()),'ServiceAccount or RBAC authority changed');
 const s=pod.spec,p=s.securityContext;
 must(s.hostNetwork===false&&s.hostPID===false&&s.hostIPC===false&&s.shareProcessNamespace===false,'host/process namespace');
 must(s.serviceAccountName===SA&&s.automountServiceAccountToken===false&&s.enableServiceLinks===false,'API authority');
 must(p?.runAsNonRoot===true&&p.runAsUser===UID&&p.runAsGroup===UID&&p.fsGroup===UID,'dedicated UID/GID');
 must(p.supplementalGroupsPolicy==='Strict'&&same(p.supplementalGroups,[]),'supplementary groups');
 must(p.seccompProfile?.type==='RuntimeDefault','seccomp');
 must(s.containers?.length===1&&!s.initContainers&&!s.ephemeralContainers,'container allowlist');
 const c=s.containers[0];must(same(c.securityContext,security),'container securityContext');
 must(same(c.resources,candidatePod().spec.containers[0].resources),'resource budget');
 must(same(s.volumes,candidatePod().spec.volumes)&&same(c.volumeMounts,candidatePod().spec.containers[0].volumeMounts),'mount whitelist');
 must(same(networkPolicy,candidateNetworkPolicy()),'network policy widened or absent');
 must(same(s.affinity,candidatePod().spec.affinity)&&!s.nodeSelector&&!s.nodeName&&!s.tolerations,'architecture and taint boundary');
 const expected=candidatePod();expected.spec.containers[0].image=c.image;
 must(same(pod,expected),'unknown Pod field or changed trusted command');
 if(reviewOnly)must(c.image===UNRESOLVED_IMAGE,'review must retain missing image evidence');
 else must(typeof approvedImage==='string'&&/^127\.0\.0\.1:30050\/platform-security\/gitleaks-validation-agent@sha256:[a-f0-9]{64}$/.test(approvedImage)&&c.image===approvedImage,'no reviewed final image digest');
 return {classification:'OFFLINE_STATIC_CONTRACT_ONLY',configuration:'PASS',runtimeIdentity:'NOT_TESTED',deployable:false};
}
export function validateFixtureFiles(files){
 must(Array.isArray(files)&&files.length<=16,'fixture count');
 for(const f of files){
  must(typeof f.path==='string'&&f.path.length>0&&!f.path.startsWith('/')&&!/[\\\x00]/.test(f.path)&&!f.path.split('/').some(s=>['..','.',''].includes(s)||s==='.git'||s.startsWith('.gitleaks')),'fixture path escape/config override');
  must(f.type==='file'&&f.executable===false&&!Object.hasOwn(f,'target'),'fixture must be passive regular data');
  must(Number.isSafeInteger(f.bytes)&&f.bytes>=0&&f.bytes<=65536,'fixture size');
 }
 must(new Set(files.map(f=>f.path)).size===files.length,'duplicate source path');
 return true;
}
export function validateBinding(b){
 must(b&&same(Object.keys(b).sort(),['agent','executors','job','label','managerRelease','mode','runBuild','trustedManifestSha256'].sort()),'binding field allowlist');
 must(b.agent===AGENT&&b.job===JOB&&b.executors===1&&b.mode==='EXCLUSIVE','job/agent identity');
 must(Number.isSafeInteger(b.runBuild)&&b.runBuild>0&&b.label===AGENT+' && security-run-'+b.runBuild,'per-build label; no fallback');
 must(b.managerRelease===RELEASE&&b.trustedManifestSha256==='e8677d348192d378de0314c4ce5edc102514dbf0ec28c13aa850d510bf514b5a','frozen Manager identity');
 return true;
}
export function validateCIRequest(parameters,ci){return resolveCI(parameters,ci);}
export function validateCleanup(x,expected){
 must(x?.source==='TRUSTED_OPERATOR_OBSERVATION'&&x.namespace===NS&&x.podUid===expected.podUid&&x.runId===expected.runId,'cleanup ownership proof');
 for(const k of ['nodeOffline','jenkinsNodeRemoved','agentSecretRemoved','podDeletionObserved','runtimeProcessesAbsent','safeArchiveVerified','privateFixtureRemoved'])must(x[k]===true,'cleanup incomplete: '+k);
 must(x.forceDeleteUsed===false&&x.namespaceDeleted===false,'unsafe cleanup');
 return true;
}
