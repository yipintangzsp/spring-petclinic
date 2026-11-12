#!/bin/bash
# W8 G-F2 installer (runs as root on devops). Idempotent. No credential
# values are printed: the SA token moves only between kubectl and the
# 0600 kubeconfig owned by security-falco.
set -eu
ROOT=/var/lib/security-falco
SRC=/tmp/w8-falco
if ! getent group security-falco >/dev/null; then groupadd -g 1007 security-falco; fi
if ! id security-falco >/dev/null 2>&1; then
  useradd -u 1007 -g 1007 -d $ROOT -s /bin/sh -M security-falco
fi
id security-falco
mkdir -p $ROOT $ROOT/.ssh $ROOT/data
install -o root -g root -m 0444 $SRC/entry.py $ROOT/entry.py
install -o root -g root -m 0444 $SRC/entry-projects.json $ROOT/entry-projects.json
chown security-falco:security-falco $ROOT/.ssh $ROOT/data
chmod 0700 $ROOT/.ssh $ROOT/data
PUB=$(cat /home/zhang/.ssh/security-manager-v2-falco.pub)
printf 'restrict,command="/usr/bin/setpriv --no-new-privs /usr/bin/python3 /var/lib/security-falco/entry.py" %s\n' "$PUB" > $ROOT/.ssh/authorized_keys
chown security-falco:security-falco $ROOT/.ssh/authorized_keys
chmod 0600 $ROOT/.ssh/authorized_keys
touch $ROOT/data/execution.lock
chown security-falco:security-falco $ROOT/data/execution.lock
kubectl apply -f $SRC/rbac.yaml
for i in $(seq 1 30); do
  TOK_B64=$(kubectl -n devsecops-system get secret security-falco-collector-token -o jsonpath='{.data.token}' 2>/dev/null || true)
  if [ -n "$TOK_B64" ]; then break; fi
  sleep 1
done
if [ -z "${TOK_B64:-}" ]; then echo "TOKEN_NOT_POPULATED"; exit 1; fi
TOKEN=$(printf '%s' "$TOK_B64" | base64 -d)
CA=$(kubectl config view --raw -o jsonpath='{.clusters[0].cluster.certificate-authority-data}')
SERVER=$(kubectl config view --raw -o jsonpath='{.clusters[0].cluster.server}')
umask 077
TMPKC=$(mktemp)
{
  printf 'apiVersion: v1\nkind: Config\nclusters:\n- name: k3s\n  cluster:\n    server: %s\n    certificate-authority-data: %s\nusers:\n- name: security-falco-collector\n  user:\n    token: %s\ncontexts:\n- name: security-falco-collector\n  context:\n    cluster: k3s\n    user: security-falco-collector\n    namespace: devsecops-system\ncurrent-context: security-falco-collector\n' "$SERVER" "$CA" "$TOKEN"
} > $TMPKC
install -o security-falco -g security-falco -m 0600 $TMPKC $ROOT/kubeconfig.yaml
rm -f $TMPKC
unset TOKEN TOK_B64
echo "== layout =="
ls -la $ROOT $ROOT/.ssh
echo "== kubeconfig stat =="
stat -c '%U %G %a %n' $ROOT/kubeconfig.yaml
echo "== can-i matrix (as SA) =="
SA=system:serviceaccount:devsecops-system:security-falco-collector
for spec in \
  "get pods devsecops-system" "list pods devsecops-system" \
  "get pods/log devsecops-system" "get daemonsets devsecops-system" \
  "list pods petclinic" "get pods petclinic" "get nodes ''" \
  "list secrets devsecops-system" "list secrets petclinic" \
  "get pods kube-system" "list nodes ''" "create pods devsecops-test" \
  "get pods/log petclinic" "delete pods devsecops-system" \
  "list daemonsets devsecops-system" "get secrets devsecops-system" ; do
  set -- $spec
  if [ -n "$3" ]; then OUT=$(kubectl auth can-i $1 $2 --as=$SA -n $3); else OUT=$(kubectl auth can-i $1 $2 --as=$SA); fi
  echo "can-i $1 $2 ns=${3:-<cluster>} -> $OUT"
done
echo "== direct kubectl via dedicated kubeconfig =="
kubectl --kubeconfig $ROOT/kubeconfig.yaml -n devsecops-system get pods -l app.kubernetes.io/name=falco -o name
kubectl --kubeconfig $ROOT/kubeconfig.yaml auth whoami 2>/dev/null || true
echo INSTALL_DONE
