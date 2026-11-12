#!/bin/bash
set -u
W=/tmp/sc2; mkdir -p $W/kyv; cd $W
U=$(jq -r .username /var/lib/security-trivy/credentials.json)
P=$(jq -r .password /var/lib/security-trivy/credentials.json)
REG=core.harbor.domain; FIX=petclinic/signature-fixtures
{
echo "KYVERNO started $(date -u +%Y-%m-%dT%H:%M:%SZ)"
TAGS=$(curl -s --insecure -u "$U:$P" https://$REG/v2/$FIX/tags/list | python3 -c "import json,sys; print(' '.join(json.load(sys.stdin)['tags']))")
LATEST=$(echo $TAGS | tr ' ' '\n' | grep signed | sort -t- -k2 -n | tail -1 | cut -d- -f2)
echo "LATEST_FIXTURE_BUILD $LATEST"
for kind in signed unsigned wrong-key; do
  D=$(curl -s -I --insecure -u "$U:$P" -H "Accept: application/vnd.oci.image.manifest.v1+json" https://$REG/v2/$FIX/manifests/ci-$LATEST-$kind | grep -i docker-content-digest | tr -d '\r' | awk '{print $2}')
  echo "FIXTURE $kind digest=$D"
  eval "D_$kind=$D"
done
CAND=sha256:2fbaea65ab030c56c60c62e3ee9fbe362deb8bbbb8216a891ef4c7bbbcea6d55
mkpod(){ printf '{"apiVersion":"v1","kind":"Pod","metadata":{"name":"%s","namespace":"devsecops-supply-chain"},"spec":{"automountServiceAccountToken":false,"restartPolicy":"Never","containers":[{"name":"probe","image":"%s","command":["/never-executed"]}]}}' "$1" "$2"; }
run_case(){
  local name=$1 image=$2
  mkpod $name "$image" > kyv/pod-$name.json
  sudo -n kubectl create --dry-run=server -f kyv/pod-$name.json -o json > kyv/dryrun-$name.out 2> kyv/dryrun-$name.err; echo "DRYRUN $name rc=$? image=$image"
  head -c 400 kyv/dryrun-$name.err; echo
}
run_case sc2-signed "core.harbor.domain/$FIX@$D_signed"
run_case sc2-unsigned "core.harbor.domain/$FIX@$D_unsigned"
run_case sc2-wrongkey "core.harbor.domain/$FIX@$D_wrongkey"
run_case sc2-candidate "core.harbor.domain/petclinic/petclinic@$CAND"
# Real create for the signed positive case, then immediate delete.
mkpod sc2-signed-real "core.harbor.domain/$FIX@$D_signed" > kyv/pod-real.json
sudo -n kubectl create -f kyv/pod-real.json > kyv/real-create.out 2> kyv/real-create.err; echo "REAL_CREATE signed rc=$?"
cat kyv/real-create.out kyv/real-create.err
sudo -n kubectl delete pod sc2-signed-real -n devsecops-supply-chain --ignore-not-found > kyv/real-delete.out 2>&1; echo "REAL_DELETE rc=$?"; cat kyv/real-delete.out
sudo -n kubectl get pods -n devsecops-supply-chain 2>&1 | head -n 3
echo "KYVERNO done $(date -u +%Y-%m-%dT%H:%M:%SZ)"
} 2>&1 | tee $W/kyv/kyverno.log
