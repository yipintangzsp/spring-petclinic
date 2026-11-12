#!/bin/bash
# Grafana datasource-proxy recheck for ZAP V2 Loki deliveries.
# Credentials come from the kube-stack-grafana k8s secret and are used only
# inside this devops session shell; they are never printed or written.
set -u
KC="sudo kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml"
GU=$($KC -n monitoring get secret kube-stack-grafana -o jsonpath='{.data.admin-user}' | base64 -d)
GP=$($KC -n monitoring get secret kube-stack-grafana -o jsonpath='{.data.admin-password}' | base64 -d)
if [ -z "$GU" ] || [ -z "$GP" ]; then echo '{"error":"GRAFANA_SECRET_UNAVAILABLE"}'; exit 1; fi
check() {
  local case_id="$1" run_id="$2" result_digest="$3" expect_identity="$4"
  local q="{service_name=\"security-manager-v2\",environment=\"validation\",schema_version=\"1\",job=\"devsecops-security-v2\"} | json | runId=\"$run_id\" | resultDigest=\"$result_digest\""
  local now start end
  now=$(date +%s); start=$(( (now-7200) * 1000000000 )); end=$(( (now+600) * 1000000000 ))
  local out http
  out=$(curl -s -w '\n%{http_code}' -u "$GU:$GP" -G 'http://127.0.0.1:30084/api/datasources/proxy/uid/loki/loki/api/v1/query_range' --data-urlencode "query=$q" --data-urlencode "start=$start" --data-urlencode "end=$end" --data-urlencode 'limit=10')
  http=$(printf '%s' "$out" | tail -1)
  printf '%s' "$out" | sed '$d' | CASE_ID="$case_id" RUN_ID="$run_id" HTTP="$http" EXPECT="$expect_identity" QUERY="$q" python3 -c '
import json,sys,os
raw=sys.stdin.read()
try: d=json.loads(raw)
except Exception: d=None
matched=0; identity=None; decision=None
if d and d.get("status")=="success":
    for stream in d["data"]["result"]:
        for ts,line in stream["values"]:
            matched+=1
            try:
                e=json.loads(line); identity=e.get("eventIdentity"); decision=e.get("policyDecision")
            except Exception: pass
print(json.dumps({"via":"grafana-datasource-proxy","datasourceUid":"loki","httpStatus":int(os.environ["HTTP"]),"query":os.environ["QUERY"],"runId":os.environ["RUN_ID"],"caseId":os.environ["CASE_ID"],"matched":matched,"eventIdentity":identity,"expectedEventIdentity":os.environ["EXPECT"],"eventIdentityMatch":identity==os.environ["EXPECT"],"policyDecision":decision},indent=1))
'
}
check clean web-6e277bfd-e875-407e-92b8-6fe9be8bdbcd 0800f06bdff64b60aa8a1ae44b9841f8c0ddc448ee16bfd595976d689aa85432 b6d5f31c957ba12f0c6b76047ab7b80f20dc77547c50e9ee020ec76b11805545
check pii-disclosure web-4f20c54a-da7b-43a3-b5fb-168ff08e2836 88fa9a4075ac193a7fab41febe42e3e724ec28262fd8d99e16f5d2d3c1b89e11 d8f39007e61ff33a65a457b8395df8ae56f31354a2c601f25c2f78db7dbeb23c
unset GU GP
