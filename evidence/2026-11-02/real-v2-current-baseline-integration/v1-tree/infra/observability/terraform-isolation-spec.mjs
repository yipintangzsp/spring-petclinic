export const namespace='terraform-execution';
export const sandboxLabel={'petclinic.devops.local/execution-sandbox':'true'};
const owner={'petclinic.devops.local/owner':'terraform-isolation'};
export function jobSpec({name,image,mode,source,api,canary,deadline=180}){
 if(!/^tf-[a-z0-9-]+$/.test(name)||!/^127\.0\.0\.1:30050\/petclinic\/terraform-runner@sha256:[a-f0-9]{64}$/.test(image)||!['plan','shared','failure','deadline'].includes(mode)||!/^[a-f0-9]{40}$/.test(source)||api!=='https://10.0.0.3:6443'||!/^10\.42\.0\.\d+$/.test(canary))throw Error('Invalid isolated execution inputs');
 const spec={serviceAccountName:'terraform-runner',automountServiceAccountToken:false,hostNetwork:false,hostPID:false,hostIPC:false,shareProcessNamespace:false,restartPolicy:'Never',terminationGracePeriodSeconds:15,nodeSelector:{'kubernetes.io/hostname':'devops','kubernetes.io/arch':'arm64'},dnsPolicy:'None',dnsConfig:{nameservers:['127.0.0.1']},securityContext:{runAsNonRoot:true,runAsUser:65532,runAsGroup:65532,fsGroup:65532,seccompProfile:{type:'RuntimeDefault'}},containers:[{name:'terraform',image,imagePullPolicy:'IfNotPresent',command:['python3','-u','/opt/terraform/worker.py'],env:[{name:'EXECUTION_MODE',value:mode},{name:'API_SERVER',value:api},{name:'CANARY_IP',value:canary},{name:'SOURCE_REVISION',value:source}],resources:{requests:{cpu:'100m',memory:'384Mi','ephemeral-storage':'128Mi'},limits:{cpu:'1',memory:'512Mi','ephemeral-storage':'384Mi'}},securityContext:{seccompProfile:{type:'RuntimeDefault'},allowPrivilegeEscalation:false,readOnlyRootFilesystem:true,capabilities:{drop:['ALL']},appArmorProfile:{type:'RuntimeDefault'}},volumeMounts:[{name:'work',mountPath:'/work'},{name:'identity',mountPath:'/var/run/terraform-identity',readOnly:true}]}],volumes:[{name:'work',emptyDir:{sizeLimit:'256Mi'}},{name:'identity',projected:{defaultMode:288,sources:[{serviceAccountToken:{path:'token',expirationSeconds:600}},{configMap:{name:'kube-root-ca.crt',items:[{key:'ca.crt',path:'ca.crt'}]}}]}}]};
 return {apiVersion:'batch/v1',kind:'Job',metadata:{name,namespace,labels:{...owner,'petclinic.devops.local/run':name}},spec:{backoffLimit:0,activeDeadlineSeconds:deadline,ttlSecondsAfterFinished:86400,template:{metadata:{labels:{...owner,'petclinic.devops.local/run':name}},spec}}};
}
export function admissionPolicies(image){
 if(!/^127\.0\.0\.1:30050\/petclinic\/terraform-runner@sha256:[a-f0-9]{64}$/.test(image))throw Error('Digest pin required');
 const objects=[];
 const make=(name,group,resource,selector,conditions,validations)=>{
  objects.push({apiVersion:'admissionregistration.k8s.io/v1',kind:'ValidatingAdmissionPolicy',metadata:{name,labels:owner},spec:{failurePolicy:'Fail',matchConstraints:{...(selector?{namespaceSelector:{matchLabels:selector}}:{}),resourceRules:[{apiGroups:[group],apiVersions:['v1'],operations:['CREATE','UPDATE'],resources:resource==='pods'?['pods','pods/ephemeralcontainers']:[resource]}]},...(conditions.length?{matchConditions:conditions.map((expression,i)=>({name:'scope-'+i,expression}))}:{}),validations:validations.map(expression=>({expression,reason:'Forbidden',message:'terraform-isolation: restricted executor contract required'}))}});
  objects.push({apiVersion:'admissionregistration.k8s.io/v1',kind:'ValidatingAdmissionPolicyBinding',metadata:{name,labels:owner},spec:{policyName:name,validationActions:['Deny','Audit']}});
 };
 for(const [resource,group,prefix] of [['pods','','object.spec'],['jobs','batch','object.spec.template.spec']]){
  const p=prefix,c=p+'.containers[0]';
  const checks=[`${p}.serviceAccountName == 'terraform-runner' && has(${p}.automountServiceAccountToken) && ${p}.automountServiceAccountToken == false`,
   `(!has(${p}.hostNetwork) || !${p}.hostNetwork) && (!has(${p}.hostPID) || !${p}.hostPID) && (!has(${p}.hostIPC) || !${p}.hostIPC) && (!has(${p}.shareProcessNamespace) || !${p}.shareProcessNamespace)`,
   `${p}.containers.size() == 1 && (!has(${p}.initContainers) || ${p}.initContainers.size() == 0) && (!has(${p}.ephemeralContainers) || ${p}.ephemeralContainers.size() == 0)`,
   `${c}.image == '${image}' && ${c}.command == ['python3','-u','/opt/terraform/worker.py'] && (!has(${c}.args) || ${c}.args.size() == 0)`,
   `has(${c}.securityContext.seccompProfile) && ${c}.securityContext.seccompProfile.type == 'RuntimeDefault'`,
   `${p}.securityContext.runAsNonRoot && ${p}.securityContext.runAsUser == 65532 && ${p}.securityContext.runAsGroup == 65532 && ${p}.securityContext.fsGroup == 65532 && has(${p}.securityContext.seccompProfile) && ${p}.securityContext.seccompProfile.type == 'RuntimeDefault'`,
   `${c}.securityContext.readOnlyRootFilesystem && ${c}.securityContext.allowPrivilegeEscalation == false && ${c}.securityContext.capabilities.drop == ['ALL'] && (!has(${c}.securityContext.capabilities.add) || ${c}.securityContext.capabilities.add.size() == 0) && has(${c}.securityContext.appArmorProfile) && ${c}.securityContext.appArmorProfile.type == 'RuntimeDefault'`,
   `${p}.volumes.all(v, has(v.emptyDir) || (has(v.projected) && v.projected.sources.all(s, has(s.serviceAccountToken) || (has(s.configMap) && s.configMap.name == 'kube-root-ca.crt'))))`,
   `${c}.env.all(e, e.name in ['EXECUTION_MODE','API_SERVER','CANARY_IP','SOURCE_REVISION'] && has(e.value) && !has(e.valueFrom)) && (!has(${c}.envFrom) || ${c}.envFrom.size() == 0)`,
   `(!has(${c}.securityContext.runAsUser) || ${c}.securityContext.runAsUser == 65532) && (!has(${c}.securityContext.runAsGroup) || ${c}.securityContext.runAsGroup == 65532) && (!has(${c}.securityContext.privileged) || !${c}.securityContext.privileged) && (!has(${c}.securityContext.procMount) || ${c}.securityContext.procMount == 'Default')`,
   `!has(${c}.lifecycle) && !has(${c}.livenessProbe) && !has(${c}.readinessProbe) && !has(${c}.startupProbe) && (!has(${c}.terminationMessagePath) || ${c}.terminationMessagePath == '/dev/termination-log')`,
   `${p}.nodeSelector['kubernetes.io/hostname'] == 'devops' && ${p}.nodeSelector['kubernetes.io/arch'] == 'arm64'`,
   `${p}.dnsPolicy == 'None' && (!has(${p}.imagePullSecrets) || ${p}.imagePullSecrets.size() == 0)`,
   `(!has(${p}.securityContext.supplementalGroups) || ${p}.securityContext.supplementalGroups.size() == 0)`];
  make('terraform-isolation-'+resource,group,resource,sandboxLabel,[],checks);
 }
 make('terraform-isolation-runtime-binding','rbac.authorization.k8s.io','rolebindings',null,["request.namespace in ['terraform-state','tf-remote-lab'] && object.metadata.name == 'terraform-runtime'"],["object.roleRef.kind == 'Role' && object.roleRef.name == 'terraform-runtime' && object.subjects.size() == 1 && object.subjects[0].kind == 'ServiceAccount' && object.subjects[0].name == 'terraform-runner' && object.subjects[0].namespace == 'terraform-execution'"]);
 return {apiVersion:'v1',kind:'List',items:objects};
}
