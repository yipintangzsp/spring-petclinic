#!/bin/bash
# Runs on devops. Grafana admin credentials are read from the kube-stack
# secret and used only inside this session; never printed or persisted.
# Args: RUN_ID OUT PLUGIN START_NS(optional)
set -eu
RUN_ID="$1"; OUT="$2"; PLUGIN="${3:-sonarqube}"; HOURS="${4:-6}"
U=$(kubectl --kubeconfig ~/.kube/config -n monitoring get secret kube-stack-grafana -o jsonpath='{.data.admin-user}' | base64 -d)
P=$(kubectl --kubeconfig ~/.kube/config -n monitoring get secret kube-stack-grafana -o jsonpath='{.data.admin-password}' | base64 -d)
END=$(date +%s)000000000; START_NS=$(( ($(date +%s) - HOURS*3600) * 1000000000 ))
Q="{job=\"devsecops-security-v2\", plugin=\"$PLUGIN\"} |= \"$RUN_ID\""
curl -s -u "$U:$P" -G "http://127.0.0.1:30084/api/datasources/proxy/uid/loki/loki/api/v1/query_range" --data-urlencode "query=$Q" --data-urlencode "start=$START_NS" --data-urlencode "end=$END" --data-urlencode "limit=50" > "$OUT"
python3 - "$OUT" <<'PY'
import json,sys
d=json.load(open(sys.argv[1]))
res=d.get('data',{}).get('result',[])
n=sum(len(s.get('values',[])) for s in res)
print('GRAFANA_STREAMS',len(res),'MATCHED',n)
for s in res:
  for ts,line in s.get('values',[]):
    e=json.loads(line)
    print('EVENT',e.get('runId'),e.get('pluginId'),e.get('policyDecision'),e.get('resultDigest'),e.get('eventIdentity'))
PY
