#!/bin/bash
set -u
KC="sudo -n kubectl"
HM="sudo -n env KUBECONFIG=/etc/rancher/k3s/k3s.yaml helm"
CHART=/tmp/w10/charts/petclinic
echo "== T0 state (revision 1, replicas 1) =="; date -Is
$KC get pods -n helm-verify -o wide
$KC get deploy petclinic -n helm-verify -o jsonpath='replicas={.spec.replicas} ready={.status.readyReplicas} image={.spec.template.spec.containers[0].image}{"\n"}'
$HM history petclinic -n helm-verify

echo "== helm upgrade: replicaCount 1 -> 2 (harmless value) =="
$HM upgrade petclinic $CHART -n helm-verify -f $CHART/values-prod.yaml -f /tmp/w10/values-nonprod.yaml --set replicaCount=2 --wait --timeout 6m
echo "upgrade_exit=$?"
$KC wait deployment/petclinic -n helm-verify --for=condition=Available --timeout=240s
$KC get pods -n helm-verify -o wide
$KC get deploy petclinic -n helm-verify -o jsonpath='replicas={.spec.replicas} ready={.status.readyReplicas}{"\n"}'
$HM history petclinic -n helm-verify

echo "== helm rollback to revision 1 =="
$HM rollback petclinic 1 -n helm-verify --wait --timeout 6m
echo "rollback_exit=$?"
$KC wait deployment/petclinic -n helm-verify --for=condition=Available --timeout=240s
sleep 10
$KC get pods -n helm-verify -o wide
$KC get deploy petclinic -n helm-verify -o jsonpath='replicas={.spec.replicas} ready={.status.readyReplicas}{"\n"}'
$HM history petclinic -n helm-verify
$HM list -n helm-verify

echo "== HTTP re-check after rollback =="
CIP=$($KC get svc petclinic -n helm-verify -o jsonpath='{.spec.clusterIP}')
curl -s -m 10 -w '\nhealth HTTP_CODE=%{http_code}\n' "http://$CIP/actuator/health"
echo "== rollback drill done =="; date -Is
