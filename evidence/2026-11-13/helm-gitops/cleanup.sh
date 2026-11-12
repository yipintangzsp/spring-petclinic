#!/bin/bash
set -u
KC="sudo -n kubectl"
HM="sudo -n env KUBECONFIG=/etc/rancher/k3s/k3s.yaml helm"
echo "== date =="; date -Is
echo "== delete temporary Argo Application =="
$KC delete application petclinic-helm-verify -n argocd --timeout=120s 2>&1
$KC get application petclinic-helm-verify -n argocd 2>&1
echo "== helm uninstall nonprod release =="
$HM uninstall petclinic -n helm-verify 2>&1
echo "== delete test namespaces =="
$KC delete namespace helm-verify helm-argo-verify --timeout=180s 2>&1
echo "== verify NotFound =="
$KC get namespace helm-verify 2>&1
$KC get namespace helm-argo-verify 2>&1
$KC get pods -n helm-verify 2>&1
$KC get applications -n argocd 2>&1
echo "== production Argo app spec unchanged =="
export KUBECONFIG=/home/zhang/.kube/platform-readonly.yaml
kubectl get application petclinic -n argocd -o jsonpath='{.spec.source.path} {.spec.source.repoURL} {.spec.destination.namespace} {.status.sync.status} {.status.health.status}{"\n"}' 2>&1
echo "== cleanup done =="; date -Is
