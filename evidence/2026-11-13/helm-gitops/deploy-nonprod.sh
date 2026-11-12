#!/bin/bash
# W10 non-prod helm deploy - namespace helm-verify ONLY. No production mutation.
set -u
export KUBECONFIG=/etc/rancher/k3s/k3s.yaml
KC="sudo -n kubectl"
HM="sudo -n env KUBECONFIG=/etc/rancher/k3s/k3s.yaml helm"
CHART=/tmp/w10/charts/petclinic

echo "== date =="; date -Is
echo "== write values-nonprod.yaml =="
cat > /tmp/w10/values-nonprod.yaml <<'EOF'
# W10 non-production verification overrides (evidence artifact; NOT for production)
replicaCount: 1
ingress:
  enabled: false
monitoring:
  enabled: false
pdb:
  minAvailable: 0
EOF
cat /tmp/w10/values-nonprod.yaml

echo "== create namespace helm-verify =="
$KC create namespace helm-verify --dry-run=client -o yaml | $KC apply -f -
$KC label namespace helm-verify w10-helm-gitops=verify --overwrite

echo "== replicate required secrets by name (values piped server-side, never printed) =="
for s in petclinic-db petclinic-harbor-pull; do
  $KC get secret "$s" -n petclinic -o json \
    | jq 'del(.metadata.namespace,.metadata.resourceVersion,.metadata.uid,.metadata.creationTimestamp,.metadata.managedFields,.metadata.annotations)' \
    | $KC apply -n helm-verify -f -
done
$KC get secrets -n helm-verify

echo "== helm lint (nonprod values) =="
$HM lint $CHART -f $CHART/values-prod.yaml -f /tmp/w10/values-nonprod.yaml -n helm-verify

echo "== helm template count (nonprod) =="
$HM template petclinic $CHART -f $CHART/values-prod.yaml -f /tmp/w10/values-nonprod.yaml -n helm-verify > /tmp/w10/rendered-nonprod.yaml
grep -c '^# Source' /tmp/w10/rendered-nonprod.yaml
python3 -c "
import yaml
for d in yaml.safe_load_all(open('/tmp/w10/rendered-nonprod.yaml')):
    if d: print(d['kind'], d['metadata']['name'], d['metadata'].get('namespace'))
"

echo "== helm install --wait =="
$HM install petclinic $CHART -n helm-verify -f $CHART/values-prod.yaml -f /tmp/w10/values-nonprod.yaml --wait --timeout 6m
echo "install_exit=$?"

echo "== state after install =="
$KC get pods -n helm-verify -o wide
$KC get deploy,svc,cm,pdb -n helm-verify
$KC get endpointslice -n helm-verify -l kubernetes.io/service-name=petclinic
$HM list -n helm-verify
$HM history petclinic -n helm-verify
echo "== deploy done =="
