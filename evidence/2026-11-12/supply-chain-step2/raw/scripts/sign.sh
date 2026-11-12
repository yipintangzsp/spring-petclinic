#!/bin/bash
# Runs as root. Decrypts the platform signing bundle with the existing bootstrap
# age key, signs the exact candidate manifest bytes, then destroys key material.
# No credential value is ever printed.
set -u
W=/tmp/sc2
B=/opt/platform-security/bootstrap-20261027
D=$(mktemp -d /tmp/sc2-sign.XXXXXX); chmod 700 $D
cleanup(){ rm -rf $D; }
trap cleanup EXIT
export SOPS_AGE_KEY_FILE=$B/signing.agekey
{
echo "SIGN started $(date -u +%Y-%m-%dT%H:%M:%SZ)"
sops decrypt $B/encrypted/signing-bundle.enc.json > $D/bundle.json 2>$D/sops.err
echo "SOPS_DECRYPT rc=$?"
python3 -c "
import json,sys
b=json.load(open('$D/bundle.json'))
assert b.get('schema')==1 and b['data'].get('privateKey') and b['data'].get('password'), 'bundle shape'
open('$D/cosign.key','w').write(b['data']['privateKey'])
open('$D/pw','w').write(b['data']['password'])
print('BUNDLE_SHAPE ok')
"
chmod 600 $D/cosign.key $D/pw
export COSIGN_PASSWORD=$(cat $D/pw)
PUB=$(timeout 20 cosign public-key --key $D/cosign.key </dev/null 2>/dev/null)
if [ "$PUB" = "$(cat $W/cosign.pub)" ]; then echo "PUBLIC_KEY_MATCH cosign.pub=yes"; else echo "PUBLIC_KEY_MATCH cosign.pub=NO"; exit 9; fi
for name in index manifest-amd64 manifest-arm64; do
  timeout 30 cosign sign-blob --yes --new-bundle-format=false --use-signing-config=false --tlog-upload=false --key $D/cosign.key --output-signature $W/sigs/$name.sig $W/raw/$name.json </dev/null > $W/sigs/$name.sign.log 2>&1
  echo "SIGN_BLOB $name rc=$? sig_sha256=$(sha256sum $W/sigs/$name.sig | cut -d' ' -f1) sig_bytes=$(stat -c%s $W/sigs/$name.sig)"
done
echo "SIGN done $(date -u +%Y-%m-%dT%H:%M:%SZ)"
} 2>&1 | tee $W/raw/sign.log
chown -R zhang:zhang $W/sigs $W/raw/sign.log
ls $D 2>/dev/null; echo "TEMPDIR_REMOVED_AFTER_EXIT expected"
