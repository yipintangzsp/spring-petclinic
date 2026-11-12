#!/bin/bash
set -u
W=/tmp/sc2
B=/opt/platform-security/bootstrap-20261027
D=$(mktemp -d /tmp/sc2-sign.XXXXXX); chmod 700 $D
trap 'rm -rf $D' EXIT
export SOPS_AGE_KEY_FILE=$B/signing.agekey
{
echo "SIGNDOCS started $(date -u +%Y-%m-%dT%H:%M:%SZ)"
sops decrypt $B/encrypted/signing-bundle.enc.json > $D/bundle.json 2>/dev/null; echo "SOPS_DECRYPT rc=$?"
python3 -c "
import json
b=json.load(open('$D/bundle.json'))
assert b.get('schema')==1 and b['data'].get('privateKey') and b['data'].get('password')
open('$D/cosign.key','w').write(b['data']['privateKey']); open('$D/pw','w').write(b['data']['password'])
print('BUNDLE_SHAPE ok')"
chmod 600 $D/cosign.key $D/pw
export COSIGN_PASSWORD=$(cat $D/pw)
PUB=$(timeout 20 cosign public-key --key $D/cosign.key </dev/null 2>/dev/null)
[ "$PUB" = "$(cat $W/cosign.pub)" ] && echo "PUBLIC_KEY_MATCH cosign.pub=yes" || { echo "PUBLIC_KEY_MATCH cosign.pub=NO"; exit 9; }
for name in provenance-chain release-decision; do
  timeout 30 cosign sign-blob --yes --new-bundle-format=false --use-signing-config=false --tlog-upload=false --key $D/cosign.key --output-signature $W/docs/$name.sig $W/docs/$name.json </dev/null > $W/docs/$name.sign.log 2>&1
  echo "SIGN_BLOB $name rc=$? sig_sha256=$(sha256sum $W/docs/$name.sig | cut -d' ' -f1)"
  timeout 20 cosign verify-blob --key $W/cosign.pub --insecure-ignore-tlog=true --signature $W/docs/$name.sig $W/docs/$name.json </dev/null > $W/docs/$name.verify.log 2>&1
  echo "VERIFY_BLOB $name rc=$?"
done
echo "SIGNDOCS done $(date -u +%Y-%m-%dT%H:%M:%SZ)"
} 2>&1 | tee $W/docs/signdocs.log
chown -R zhang:zhang $W/docs
