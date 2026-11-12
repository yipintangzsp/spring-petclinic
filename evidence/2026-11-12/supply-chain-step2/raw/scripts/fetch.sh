#!/bin/bash
set -u
W=/tmp/sc2; mkdir -p $W/raw $W/sigs; cd $W
U=$(jq -r .username /var/lib/security-trivy/credentials.json)
P=$(jq -r .password /var/lib/security-trivy/credentials.json)
REG=core.harbor.domain; REPO=petclinic/petclinic
INDEX=sha256:2fbaea65ab030c56c60c62e3ee9fbe362deb8bbbb8216a891ef4c7bbbcea6d55
AMD=sha256:2bd9c1c445afbf55e390bfc41910551c32e09913143f7a137038cc87941b7c94
ARM=sha256:06a515708b6783db7d545544bbefb02e9f94abfc0fdf13a7355ccbe2deb3ed42
{
echo "FETCH started $(date -u +%Y-%m-%dT%H:%M:%SZ) host=$(hostname) user=$(whoami)"
curl -s --insecure -u "$U:$P" -H "Accept: application/vnd.oci.image.index.v1+json" https://$REG/v2/$REPO/manifests/$INDEX -o raw/index.json
echo "INDEX sha256:$(sha256sum raw/index.json | cut -d' ' -f1) expected=$INDEX"
curl -s --insecure -u "$U:$P" -H "Accept: application/vnd.oci.image.manifest.v1+json" https://$REG/v2/$REPO/manifests/$AMD -o raw/manifest-amd64.json
echo "AMD64 sha256:$(sha256sum raw/manifest-amd64.json | cut -d' ' -f1) expected=$AMD"
curl -s --insecure -u "$U:$P" -H "Accept: application/vnd.oci.image.manifest.v1+json" https://$REG/v2/$REPO/manifests/$ARM -o raw/manifest-arm64.json
echo "ARM64 sha256:$(sha256sum raw/manifest-arm64.json | cut -d' ' -f1) expected=$ARM"
for d in $INDEX $AMD $ARM; do
  tag=$(echo $d | sed 's/:/-/')
  code=$(curl -s -o /dev/null -w "%{http_code}" --insecure -u "$U:$P" -I https://$REG/v2/$REPO/manifests/$tag.sig)
  echo "SIGTAG $d tag=$tag.sig http=$code"
done
code=$(curl -s -o /dev/null -w "%{http_code}" --insecure -u "$U:$P" https://$REG/v2/$REPO/referrers/$INDEX)
echo "REFERRERS index http=$code"
sha256sum /usr/local/bin/cosign; cosign version 2>/dev/null | grep -i gitversion
cp /opt/platform-security/bootstrap-20261027/cosign.pub $W/cosign.pub 2>/dev/null || sudo -n cp /opt/platform-security/bootstrap-20261027/cosign.pub $W/cosign.pub
sudo -n chown zhang:zhang $W/cosign.pub 2>/dev/null
sha256sum $W/cosign.pub; wc -c raw/*.json
echo "FETCH done $(date -u +%Y-%m-%dT%H:%M:%SZ)"
} 2>&1 | tee $W/raw/fetch.log
