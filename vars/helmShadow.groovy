// Shadow-only helper. No deployment, GitOps write, approval or Security Manager registration.
def call(Map cfg = [:]) {
    if (params.HELM_ENABLED != true) return [status: 'DISABLED', executed: false]
    if ((params.PROMOTION_ACTION ?: 'audit-only') != 'audit-only') error('HELM_ENABLED is shadow-only; promotion forbidden')
    def phase = cfg.phase ?: 'prepare'
    if (!(phase in ['prepare','lint','render','validate','policy','candidate'])) error('Unknown Helm shadow phase')
    withEnv([
        'HELM_CHART_PATH=' + (params.HELM_CHART_PATH ?: 'charts/petclinic'),
        'HELM_VALUES_FILE=' + (params.HELM_VALUES_FILE ?: 'charts/petclinic/values-prod.yaml'),
        'HELM_RELEASE_NAME=' + (params.HELM_RELEASE_NAME ?: 'petclinic'),
        'HELM_NAMESPACE=' + (params.HELM_NAMESPACE ?: 'petclinic')
    ]) { sh "node infra/helm/pipeline.mjs ${phase}" }
    return [status: 'VALIDATED_SHADOW_PHASE', phase: phase, executed: true]
}
return this
