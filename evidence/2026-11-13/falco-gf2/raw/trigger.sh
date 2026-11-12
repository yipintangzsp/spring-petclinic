#!/bin/bash
# Controlled Falco trigger for the V2 candidate run. Creates ONE test pod in
# the pre-existing isolated test namespace devsecops-test (the only test
# namespace in Falco's platform rules scope, besides the petclinic business
# namespace), performs harmless in-container actions, and leaves the pod
# running for the driver to collect. Cleanup is a separate explicit step.
# PodSecurity restricted applies: non-root (65534), drop ALL, no privilege
# escalation. Actions: shell start (kubectl exec sh) + reading the TEST
# CONTAINER'S OWN /etc/passwd (world-readable, succeeds) and /etc/shadow
# (denied EACCES for non-root; Falco's rule covers denied attempts and the
# attempt is the evidence). Contents are never recorded. No host files,
# no writes, no privileged pod.
set -u
POD="$1"
NS=devsecops-test
IMG=127.0.0.1:30050/platform-upgrade/busybox:1.38.0-arm64
YAML=/tmp/falco-v2-pod.yaml
cat > "$YAML" <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: $POD
  namespace: $NS
  labels:
    app: falco-v2-test
spec:
  automountServiceAccountToken: false
  restartPolicy: Never
  securityContext:
    runAsNonRoot: true
    runAsUser: 65534
    runAsGroup: 65534
    seccompProfile:
      type: RuntimeDefault
  containers:
  - name: test
    image: $IMG
    command: ["sleep", "900"]
    securityContext:
      allowPrivilegeEscalation: false
      runAsNonRoot: true
      runAsUser: 65534
      capabilities:
        drop: ["ALL"]
    resources:
      limits: {cpu: "100m", memory: "64Mi"}
      requests: {cpu: "10m", memory: "16Mi"}
EOF
echo "== sensor identity before =="
sudo -n kubectl -n devsecops-system get pods -l app.kubernetes.io/name=falco -o jsonpath='{.items[0].metadata.name} {.items[0].metadata.uid} {.items[0].status.containerStatuses[0].restartCount} {.items[0].status.containerStatuses[0].state.running.startedAt}'
echo
echo "== create test pod $POD =="
sudo -n kubectl -n "$NS" delete pod "$POD" --ignore-not-found --wait=true >/dev/null 2>&1
sudo -n kubectl create -f "$YAML"
sudo -n kubectl -n "$NS" wait --for=condition=Ready "pod/$POD" --timeout=90s
sudo -n kubectl -n "$NS" get pod "$POD" -o jsonpath='podUid={.metadata.uid} node={.spec.nodeName} containerId={.status.containerStatuses[0].containerID}'
echo
burst() {
  sudo -n kubectl -n "$NS" exec "$POD" -c test -- sh -c 'cat /etc/passwd >/dev/null; cat /etc/shadow >/dev/null 2>&1; cat /etc/shadow >/dev/null 2>&1; cat /etc/passwd >/dev/null'
  sudo -n kubectl -n "$NS" exec "$POD" -c test -- sh -c 'cat /etc/shadow >/dev/null 2>&1; cat /etc/passwd >/dev/null'
}
echo "== burst 1 =="; burst; echo "burst1 done"
echo "== wait 17s =="; sleep 17
echo "== burst 2 =="; burst; echo "burst2 done"
echo "WINDOW_END_MS=$(date +%s%3N)"
echo "== sensor identity after =="
sudo -n kubectl -n devsecops-system get pods -l app.kubernetes.io/name=falco -o jsonpath='{.items[0].metadata.name} {.items[0].metadata.uid} {.items[0].status.containerStatuses[0].restartCount} {.items[0].status.containerStatuses[0].state.running.startedAt}'
echo
