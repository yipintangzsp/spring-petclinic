// Optional independently verified image-build provenance; does not replace security-validation attestation.
def call(Map cfg=[:]) {
 String mode=cfg.mode ?: 'enforce'
 if(!(mode in ['off','audit','enforce'])) error('Invalid build provenance mode')
 if(mode=='off' || cfg.enabled!=true) return [tool:'build-provenance',status:'skipped']
 def result=[tool:'build-provenance',status:'success',build:env.BUILD_NUMBER.toInteger(),mode:mode]
 stage('Verify Image Build Provenance') {
  withEnv(['BUILD_PROVENANCE_IMAGE='+(cfg.image ?: ''),'BUILD_SOURCE_COMMIT='+(cfg.commit ?: ''),'BUILD_SOURCE_REPOSITORY='+(cfg.repository ?: ''),'BUILD_BUILDER_IDENTITY='+(cfg.builder ?: ''),'BUILD_SOURCE_NUMBER='+(cfg.buildNumber ?: '')]) {
   withCredentials([usernamePassword(credentialsId:'harbor-creds',usernameVariable:'HARBOR_USER',passwordVariable:'HARBOR_PASS')]) {
    int rc=sh(script:'node infra/security/provenance/build-attestation.mjs verify',returnStatus:true)
    if(rc!=0) { result.status=mode=='audit'?'warn':'failed';if(mode=='enforce')catchError(buildResult:'FAILURE',stageResult:'FAILURE'){error('Image build provenance mismatch; approval blocked')}else echo 'WARN: image build provenance not verified' }
   }
  }
 }
 writeJSON(file:'.devsecops/build-provenance-status.json',json:result)
 return result
}
