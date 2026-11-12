#!/bin/bash
set -u
W=/tmp/sc2; cd $W
VF="--key cosign.pub --insecure-ignore-tlog=true"
{
echo "VERIFY started $(date -u +%Y-%m-%dT%H:%M:%SZ)"
for name in index manifest-amd64 manifest-arm64; do
  timeout 20 cosign verify-blob $VF --signature sigs/$name.sig raw/$name.json </dev/null > raw/verify-$name.log 2>&1; echo "POSITIVE $name rc=$?"
done
cp raw/manifest-amd64.json raw/tampered-amd64.json; printf ' ' >> raw/tampered-amd64.json
timeout 20 cosign verify-blob $VF --signature sigs/manifest-amd64.sig raw/tampered-amd64.json </dev/null > raw/verify-neg-tamper.log 2>&1; echo "NEGATIVE N1_TAMPERED_MANIFEST rc=$? (expect nonzero)"
timeout 20 cosign verify-blob $VF --signature sigs/index.sig raw/manifest-amd64.json </dev/null > raw/verify-neg-cross.log 2>&1; echo "NEGATIVE N2_INDEX_SIG_ON_CHILD rc=$? (expect nonzero)"
timeout 20 cosign verify-blob $VF --signature sigs/manifest-arm64.sig raw/manifest-amd64.json </dev/null > raw/verify-neg-archswap.log 2>&1; echo "NEGATIVE N3_ARCH_SWAP rc=$? (expect nonzero)"
cp sigs/index.sig raw/tampered.sig; printf 'A' >> raw/tampered.sig
timeout 20 cosign verify-blob $VF --signature raw/tampered.sig raw/index.json </dev/null > raw/verify-neg-tampersig.log 2>&1; echo "NEGATIVE N4_TAMPERED_SIG rc=$? (expect nonzero)"
timeout 20 cosign verify-blob $VF --signature raw/does-not-exist.sig raw/index.json </dev/null > raw/verify-neg-missing.log 2>&1; echo "NEGATIVE N5_MISSING_SIG rc=$? (expect nonzero)"
echo "VERIFY done $(date -u +%Y-%m-%dT%H:%M:%SZ)"
} 2>&1 | tee $W/raw/verify.log
tail -n 2 raw/verify-index.log raw/verify-neg-tamper.log
