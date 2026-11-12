#!/bin/bash
# Grafana datasource-proxy recheck for SOPS V2 Loki deliveries.
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
check compliant web-0ec63caa-60db-4ad6-b8d8-3cc00695f3db ef8ab10dcac9870d90c6e481e2f7932bd6a09656e2b767d1097b175556dfea90 24aa6b6c3ddd68cab25d82f45313fb4a9235dc43d907f8a1ec7b6d9282488b53
check tampered-ciphertext web-55bac243-d53e-497c-86d3-0a78c59ee004 c7cb7a1571520a43df0a36567ca1606ad28155c58ce710f073d9634eee3660b7 a8d4faddeb586dafb624c9876f1cc37f7c49ff4b55b33e6357cbee58402bd692
unset GU GP
