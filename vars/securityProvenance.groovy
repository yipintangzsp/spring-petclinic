def call(Map cfg=[:]) {
 String mode=cfg.mode ?: 'enforce'
 if(!(mode in ['off','audit','enforce']))error('Invalid provenance mode')
 def enabled=cfg.enableProvenance == true || params.get('ENABLE_PROVENANCE',false) == true || env.ENABLE_PROVENANCE == 'true'
 if(!enabled || mode=='off') return [tool:'provenance',status:'skipped']
 def result=[tool:'provenance',status:'success'];boolean failed=false
 withEnv(['PROVENANCE_CANDIDATE='+(cfg.candidateImage ?: params.get('AUDIT_CANDIDATE_IMAGE','') ?: cfg.image ?: ''),'PROVENANCE_REPOSITORY='+(cfg.repository ?: sh(script:'git config --get remote.origin.url',returnStdout:true).trim())]) {
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
