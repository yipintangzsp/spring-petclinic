#!/bin/bash
set -u
WORK=/var/lib/security-trivy/data/sbom-step1-20261112
TOOL=/var/lib/security-trivy/bin/trivy
export HOME=/var/lib/security-trivy
cd $WORK
TOOLSHA=$(sha256sum $TOOL | cut -d" " -f1)
TOOLVER=$($TOOL --version 2>/dev/null | head -1 | awk '{print $2}')
U=$(jq -r .username /var/lib/security-trivy/credentials.json)
P=$(jq -r .password /var/lib/security-trivy/credentials.json)
REG=core.harbor.domain; REPO=petclinic/petclinic
INDEX=sha256:2fbaea65ab030c56c60c62e3ee9fbe362deb8bbbb8216a891ef4c7bbbcea6d55
# assert index bytes hash to the pinned index digest
curl -s --insecure -u "$U:$P" -H "Accept: application/vnd.oci.image.index.v1+json" https://$REG/v2/$REPO/manifests/$INDEX -o index.json
GOT="sha256:$(sha256sum index.json | cut -d' ' -f1)"
echo "INDEX_ASSERT expected=$INDEX got=$GOT"
[ "$GOT" = "$INDEX" ] || { echo "INDEX_MISMATCH"; exit 3; }
declare -A TGT=( [amd64]=sha256:2bd9c1c445afbf55e390bfc41910551c32e09913143f7a137038cc87941b7c94 [arm64]=sha256:06a515708b6783db7d545544bbefb02e9f94abfc0fdf13a7355ccbe2deb3ed42 )
: > facts.txt
echo "toolVersion=$TOOLVER" >> facts.txt
echo "toolSha256=$TOOLSHA" >> facts.txt
echo "uid=$(id -u) gid=$(id -g)" >> facts.txt
for arch in amd64 arm64; do
  D=${TGT[$arch]}
  curl -s --insecure -u "$U:$P" -H "Accept: application/vnd.oci.image.manifest.v1+json" https://$REG/v2/$REPO/manifests/$D -o manifest-$arch.json
  MGOT="sha256:$(sha256sum manifest-$arch.json | cut -d' ' -f1)"
  echo "MANIFEST_ASSERT $arch expected=$D got=$MGOT"
  [ "$MGOT" = "$D" ] || { echo "MANIFEST_MISMATCH $arch"; exit 4; }
  CFG=$(jq -r .config.digest manifest-$arch.json); LAYERS=$(jq ".layers | length" manifest-$arch.json)
  START=$(date -u +%Y-%m-%dT%H:%M:%SZ); SMS=$(date +%s%3N)
  TRIVY_USERNAME="$U" TRIVY_PASSWORD="$P" $TOOL image --insecure --format cyclonedx --output $WORK/sbom-$arch.cdx.json --cache-dir $WORK/cache --skip-db-update --skip-java-db-update --timeout 10m "$REG/$REPO@$D" > $WORK/trivy-$arch.log 2>&1
  RC=$?; END=$(date -u +%Y-%m-%dT%H:%M:%SZ); EMS=$(date +%s%3N)
  echo "GEN $arch rc=$RC start=$START end=$END"
  if [ $RC -ne 0 ]; then tail -5 $WORK/trivy-$arch.log; exit 5; fi
  SHA=$(sha256sum $WORK/sbom-$arch.cdx.json | cut -d' ' -f1); BYTES=$(stat -c%s $WORK/sbom-$arch.cdx.json)
  COMPS=$(jq ".components | length" $WORK/sbom-$arch.cdx.json); SERIAL=$(jq -r ".serialNumber // \"none\"" $WORK/sbom-$arch.cdx.json)
  echo "$arch manifestDigest=$D configDigest=$CFG layers=$LAYERS sbomSha256=$SHA sbomBytes=$BYTES components=$COMPS serial=$SERIAL startedAt=$START completedAt=$END startedMs=$SMS completedMs=$EMS" >> facts.txt
done
echo "FACTS:"; cat facts.txt
