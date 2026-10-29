// Public, untrusted Shared Library entry. Caller owns node, checkout and deployment.
def call(Map cfg=[:]) {
 String mode=cfg.mode ?: 'enforce'; String profile=cfg.profile ?: 'java-web'
 if (!(mode in ['off','audit','enforce'])) error('Invalid security mode')
 def profiles=readJSON(text:libraryResource('security-manager/profiles.json'),returnPojo:true)
 if (!profiles.containsKey(profile)) error('Unknown security profile')
 if (cfg.adapter == 'petclinic' && mode != 'enforce') error('PetClinic production adapter remains enforce')
 String sourceRoot=pwd(); String runtimeRoot=sourceRoot
 if(cfg.sourceCommit && !(cfg.sourceCommit ==~ /[a-f0-9]{40}/)) error('Fixed project source commit required')
 def results=[]
 if (mode != 'off' && cfg.adapter != 'petclinic') {
  runtimeRoot=sourceRoot+'/.security-manager/runtime'
  dir(runtimeRoot) { checkout([$class:'GitSCM',branches:[[name:cfg.runtimeRevision ?: error('Pinned runtimeRevision required')]],extensions:[[$class:'CloneOption',shallow:true,depth:1,noTags:true]],userRemoteConfigs:[[url:cfg.runtimeRepository ?: 'http://gitlab-service.ns-devops.svc.cluster.local/root/petclinic-platform.git',credentialsId:cfg.gitCredential ?: 'gitlab-creds']]]) }
 }
 def plan=[]
 if(mode=='off') for(String id:profiles[profile]) results.add([tool:id,status:'disabled',reason:'mode=off'])
 if(mode!='off') {
  if(cfg.adapter=='petclinic') plan=readJSON(text:libraryResource('security-manager/petclinic-adapter.json'),returnPojo:true)
  else for (String id : profiles[profile]) {
   boolean ready=id in ['gitleaks','semgrep'] || (id=='sbom' && cfg.sbomFile) || (id in ['trivy','cosign'] && cfg.image) || (id=='sonarqube' && cfg.sonarProject && cfg.sonarCommand) || (id=='zap' && cfg.readOnlyUrls) || (id=='kubescape' && cfg.yamlPath) || (id=='defectdojo' && cfg.dojoEngagement)
   if(ready) plan.add([id:id,stage:id,command:'node infra/security/manager/tool.mjs '+id,credentials:[]])
   else results.add([tool:id,status:'not_configured',reason:'Required project target/credential settings absent; no fabricated result'])
  }
 }
 boolean ownsLease=false
 String holder=cfg.adapter=='petclinic' ? (env.HEAVY_HOLDER ?: 'jenkins-petclinic-'+env.BUILD_NUMBER) : 'manager-'+env.JOB_BASE_NAME+'-'+env.BUILD_NUMBER
 try { withEnv(['HEAVY_HOLDER='+holder]) { dir(runtimeRoot) {
  if(cfg.adapter!='petclinic') {
   sh 'mkdir -p .devsecops/gates'
   withEnv(['MANAGER_SOURCE_ROOT='+sourceRoot]) { writeFile(file:'.git-sha',text:cfg.sourceCommit ?: sh(script:'git -C "$MANAGER_SOURCE_ROOT" rev-parse HEAD',returnStdout:true).trim()) }
   writeJSON(file:'.devsecops/manager-config.json',json:cfg+[enabledModules:plan.collect{it.id},sourceRoot:sourceRoot,profile:profile,mode:mode,project:cfg.project ?: env.JOB_NAME,build:env.BUILD_NUMBER])
  }
  if(mode!='off' && cfg.adapter!='petclinic') { sh 'node infra/observability/heavy-lease.mjs acquire'; ownsLease=true }
  for (def module : plan) {
   stage('Security / '+module.stage) {
    def bindings=[]
    for(def c:module.credentials) {
     if(c.type=='string') bindings.add(string(credentialsId:c.id,variable:c.variable))
     if(c.type=='file') bindings.add(file(credentialsId:c.id,variable:c.variable))
     if(c.type=='usernamePassword') bindings.add(usernamePassword(credentialsId:c.id,usernameVariable:c.username,passwordVariable:c.password))
    }
    if(cfg.adapter!='petclinic') {
     if(module.id in ['trivy']) bindings.add(usernamePassword(credentialsId:cfg.harborCredential ?: 'harbor-creds',usernameVariable:'HARBOR_USER',passwordVariable:'HARBOR_PASS'))
     if(module.id=='sonarqube') bindings.add(string(credentialsId:cfg.sonarCredential ?: 'sonar-token',variable:'SONAR_TOKEN'))
     if(module.id=='defectdojo') bindings.add(string(credentialsId:cfg.dojoCredential ?: 'defectdojo-api-token',variable:'DEFECTDOJO_TOKEN'))
    }
    withCredentials(bindings) {
     int code=sh(script:'set +e\n'+module.command+' > .devsecops/gates/'+module.id+'.log 2>&1\nrc=$?\ncat .devsecops/gates/'+module.id+'.log\nexit "$rc"',returnStatus:true)
     boolean warning=code==10 && mode=='audit' && cfg.adapter!='petclinic'
     results.add([tool:module.id,stage:module.stage,exitCode:code,status:code==0?'success':warning?'warn':'failed',platform:module.platform ?: false])
     if(code!=0 && !warning) catchError(buildResult:'FAILURE',stageResult:'FAILURE') { error('Security module '+module.id+' failed; report archived; exit '+code) }
     if(warning) echo('AUDIT finding retained: '+module.id)
    }
   }
  }
  stage('Security Gate') {
   if(mode=='enforce' && cfg.adapter!='petclinic' && results.any{it.status=='not_configured'}) catchError(buildResult:'FAILURE',stageResult:'FAILURE') { error('Enforce requires settings for every selected profile module') }
   writeJSON(file:'.devsecops/security-manager.json',json:[schema:1,mode:mode,profile:profile,adapter:cfg.adapter ?: 'generic',project:cfg.project ?: env.JOB_NAME,modules:results,optionalScansExecuted:plan.size(),promotionAllowed:cfg.adapter=='petclinic' && mode=='enforce' && !results.any{it.status=='failed'}])
   if(cfg.adapter!='petclinic') {
    writeFile(file:'.security-manager-summary.mjs',text:libraryResource('security-manager/summary.mjs'))
    withEnv(['SECURITY_BUILD_RESULT='+currentBuild.currentResult]) { sh 'node .security-manager-summary.mjs' }
   }
   archiveArtifacts(artifacts:'.devsecops/**',allowEmptyArchive:true)
  }
 }
 } } finally { if(ownsLease) dir(runtimeRoot) { withEnv(['HEAVY_HOLDER='+holder]) { sh 'node infra/observability/heavy-lease.mjs release' } } }
 return results
}
