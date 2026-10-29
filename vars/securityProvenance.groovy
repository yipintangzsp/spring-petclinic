def call(Map cfg=[:]) {
 String mode=cfg.mode ?: 'enforce'
 if(!(mode in ['off','audit','enforce']))error('Invalid provenance mode')
 def enabled=params.containsKey('ENABLE_PROVENANCE') ? params.ENABLE_PROVENANCE == true : env.ENABLE_PROVENANCE != null ? env.ENABLE_PROVENANCE == 'true' : cfg.enableProvenance == true
 if(!enabled || mode=='off') return [tool:'provenance',status:'skipped']
 String sourceRoot=cfg.sourceRoot ?: pwd()
 def repository
 def commit
 withEnv(['PROVENANCE_SOURCE_ROOT='+sourceRoot]) { repository=cfg.repository ?: sh(script:'git -C "$PROVENANCE_SOURCE_ROOT" config --get remote.origin.url',returnStdout:true).trim(); commit=sh(script:'git -C "$PROVENANCE_SOURCE_ROOT" rev-parse HEAD',returnStdout:true).trim() }
 def result=[tool:'provenance',status:'success'];boolean failed=false
 withEnv(['PROVENANCE_CANDIDATE='+(cfg.candidateImage ?: params.get('AUDIT_CANDIDATE_IMAGE','') ?: cfg.image ?: ''),'PROVENANCE_REPOSITORY='+repository,'PROVENANCE_COMMIT='+commit]) {
  for(def action:['generate','create','verify']) {
   stage(['generate':'Generate Provenance','create':'Create Attestation','verify':'Verify Attestation'][action]) {
    if(failed) { echo 'SKIPPED: earlier provenance operation failed' }
    else {
     def code
     if(action=='create') withCredentials([file(credentialsId:'platform-signing-age',variable:'SIGNING_AGE_FILE'),usernamePassword(credentialsId:'harbor-creds',usernameVariable:'HARBOR_USER',passwordVariable:'HARBOR_PASS')]) { code=sh(script:'node infra/security/provenance/plugin.mjs '+action,returnStatus:true) }
     else code=sh(script:'node infra/security/provenance/plugin.mjs '+action,returnStatus:true)
     if(code!=0) { failed=true;result.status=mode=='audit'?'warn':'failed';if(mode=='enforce')catchError(buildResult:'FAILURE',stageResult:'FAILURE'){error('Provenance validation failed; approval blocked')}else echo 'WARN: provenance validation failed' }
    }
   }
  }
 }
 writeJSON(file:'.devsecops/provenance-status.json',json:result)
 return result
}
