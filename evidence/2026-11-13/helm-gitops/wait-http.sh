#!/bin/bash
set -u
KC="sudo -n kubectl"
echo "== date =="; date -Is
echo "== kubectl wait deployment available (timeout 240s) =="
$KC wait deployment/petclinic -n helm-verify --for=condition=Available --timeout=240s
echo "wait_exit=$?"
$KC get pods -n helm-verify -o wide
$KC get deploy,svc -n helm-verify
$KC get endpointslice -n helm-verify -l kubernetes.io/service-name=petclinic
echo "== curl via ClusterIP from devops host (svc petclinic.helm-verify) =="
CIP=$($KC get svc petclinic -n helm-verify -o jsonpath='{.spec.clusterIP}')
echo "clusterIP=$CIP"
for i in 1 2 3 4 5; do
  code=$(curl -s -m 10 -o /tmp/w10/health.json -w '%{http_code}' "http://$CIP/actuator/health" || echo 000)
  echo "attempt $i health http=$code"
  if [ "$code" = "200" ]; then break; fi
  sleep 5
done
cat /tmp/w10/health.json; echo
curl -s -m 10 -o /tmp/w10/root.html -w 'root HTTP_CODE=%{http_code} SIZE=%{size_download}\n' "http://$CIP/"
grep -o '<title>[^<]*</title>' /tmp/w10/root.html | head -n 2
echo "== readiness endpoint =="
curl -s -m 10 -w '\nreadiness HTTP_CODE=%{http_code}\n' "http://$CIP/actuator/health/readiness"
echo "== done =="; date -Is
