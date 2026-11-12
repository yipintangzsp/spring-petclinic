#!/bin/bash
set -u
KC="sudo -n kubectl"
echo "== date =="; date -Is
echo "== prep namespace helm-argo-verify + secrets (values piped, never printed) =="
$KC create namespace helm-argo-verify --dry-run=client -o yaml | $KC apply -f -
for s in petclinic-db petclinic-harbor-pull; do
  $KC get secret "$s" -n petclinic -o json \
    | jq 'del(.metadata.namespace,.metadata.resourceVersion,.metadata.uid,.metadata.creationTimestamp,.metadata.managedFields,.metadata.annotations)' \
    | $KC apply -n helm-argo-verify -f -
done

cat > /tmp/w10/argo-helm-verify-app.yaml <<'EOF'
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: petclinic-helm-verify
  namespace: argocd
  labels:
    petclinic.devops.local/status: VALIDATION_ONLY
    petclinic.devops.local/scope: W10-NONPROD
  finalizers:
    - resources-finalizer.argocd.argoproj.io
spec:
  project: default
  source:
    repoURL: http://gitlab-service.ns-devops.svc.cluster.local/root/petclinic-platform.git
    targetRevision: main
    path: charts/petclinic
    helm:
      releaseName: petclinic
      valueFiles:
        - values-prod.yaml
      parameters:
        - name: replicaCount
          value: "1"
        - name: ingress.enabled
          value: "false"
        - name: monitoring.enabled
          value: "false"
        - name: pdb.minAvailable
          value: "0"
  destination:
    server: https://kubernetes.default.svc
    namespace: helm-argo-verify
  syncPolicy:
    automated:
      prune: true
      selfHeal: true
    syncOptions:
      - CreateNamespace=false
EOF
echo "== apply temporary Application =="
$KC apply -f /tmp/w10/argo-helm-verify-app.yaml

echo "== poll sync/health up to ~240s =="
for i in $(seq 1 24); do
  sleep 10
  line=$($KC get application petclinic-helm-verify -n argocd -o jsonpath='{.status.sync.status} {.status.health.status} {.status.operationState.phase} {.status.sync.revision}' 2>/dev/null)
  echo "poll $i: $line"
  sync=$(echo "$line" | awk '{print $1}'); health=$(echo "$line" | awk '{print $2}')
  if [ "$sync" = "Synced" ] && [ "$health" = "Healthy" ]; then echo "ARGO_SYNC_HEALTHY"; break; fi
done
echo "== app conditions (errors if any) =="
$KC get application petclinic-helm-verify -n argocd -o jsonpath='{range .status.conditions[*]}{.type}: {.message}{"\n"}{end}' 2>/dev/null | cut -c1-500
echo "== resources in helm-argo-verify =="
$KC get pods,deploy,svc,cm,pdb -n helm-argo-verify 2>&1
echo "== http check via ClusterIP =="
CIP=$($KC get svc petclinic -n helm-argo-verify -o jsonpath='{.spec.clusterIP}' 2>/dev/null)
echo "clusterIP=$CIP"
if [ -n "$CIP" ]; then
  for i in 1 2 3 4 5 6; do
    code=$(curl -s -m 10 -o /tmp/w10/argo-health.json -w '%{http_code}' "http://$CIP/actuator/health" || echo 000)
    echo "attempt $i http=$code"
    if [ "$code" = "200" ]; then cat /tmp/w10/argo-health.json; echo; break; fi
    sleep 8
  done
fi
echo "== argo test capture done =="; date -Is
