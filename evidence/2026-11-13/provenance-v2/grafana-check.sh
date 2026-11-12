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
check historical-candidate web-e8a79056-0b07-4f3b-8073-6d050952bbea eb700a5423736c8fc891ca1a05f5e211391669e6e21217151c0b1b7eb27c7660 a86bd61836d81b0a0e06e16bb1c65f66b75ac8988bec143bbda1ce6074f7ad16
check wrong-digest web-9bd484e3-1228-4998-b32c-5d2b9aea48af 88b24d0a8ad43428002eb24d9094354f040a3a53c06458900f07ea3b8f966812 1aed19a58ee9e6eb9b7a866f6917576712922921ca48e768839beffe46c90703
unset GU GP
