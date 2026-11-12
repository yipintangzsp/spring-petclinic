#!/bin/bash
# Grafana datasource-proxy recheck for V2 Loki deliveries.
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
  printf '%s' "$out" | sed '$d' | CASE_ID="$case_id" RUN_ID="$run_id" HTTP="$http" EXPECT="$expect_identity" python3 -c '
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
print(json.dumps({"via":"grafana-datasource-proxy","datasourceUid":"loki","httpStatus":int(os.environ["HTTP"]),"runId":os.environ["RUN_ID"],"caseId":os.environ["CASE_ID"],"matched":matched,"eventIdentity":identity,"expectedEventIdentity":os.environ["EXPECT"],"eventIdentityMatch":identity==os.environ["EXPECT"],"policyDecision":decision},indent=1))
'
}
check historical-build web-8973a0d3-7d2f-48d7-95ba-b99933b0dc7d 3cfb365db85d151709f5cd89da738737f4381a259c39e4f44daa069a128b4d10 6398554badab4faa4bccbc00dfffc64f19fedf0922184cf69ee475fd513c1664
check wrong-digest web-52b5d426-1a48-4836-afa1-3723703afff0 8d92fd3d3cada56425dc582b6c9dcdd055cd90439ad0ff6e73086e5a3046968f 833bd7d0d4f7a1e36f4608670ed42bf611693f1c5e360a01a260606a8fc9734a
unset GU GP
