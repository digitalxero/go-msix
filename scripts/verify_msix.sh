#!/usr/bin/env bash
# External cross-check of go-msix signed output against osslsigncode, which
# independently recomputes the APPX digests (AXPC/AXCD/AXCT/AXBM) from the
# package bytes and compares them to the digest table inside AppxSignature.p7x.
#
# IMPORTANT: a bare "Succeeded" is NOT sufficient — osslsigncode accepts a
# malformed pkcs7-data envelope without ever comparing APPX digests (that is
# exactly the bug class this script exists to catch). We therefore require all
# four "Checking ... hashes" comparison blocks to be present AND a tamper test
# to fail. Uses native osslsigncode when installed AND it prints the digest
# comparisons; otherwise a pinned osslsigncode 2.14 built from source in Docker.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

fail() { echo "FAIL: $*" >&2; exit 1; }

OSSL_IMAGE=go-msix-osslsigncode-2.14
build_image() {
    docker image inspect "$OSSL_IMAGE" >/dev/null 2>&1 && return 0
    docker build -t "$OSSL_IMAGE" - <<'EOF'
FROM ubuntu:24.04
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates git cmake gcc make libssl-dev libcurl4-openssl-dev zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*
RUN git clone --depth 1 --branch 2.14 https://github.com/mtrojnar/osslsigncode.git /src \
    && cmake -S /src -B /build -DCMAKE_BUILD_TYPE=Release \
    && cmake --build /build --parallel \
    && cmake --install /build
ENTRYPOINT ["osslsigncode"]
EOF
}

OSSL=""
if command -v osslsigncode >/dev/null; then
    echo "==> using native osslsigncode ($(osslsigncode --version 2>&1 | head -1))"
    OSSL() { (cd "$WORK" && osslsigncode "$@"); }
    OSSL=native
elif command -v docker >/dev/null; then
    echo "==> using dockerized osslsigncode 2.14 ($OSSL_IMAGE)"
    build_image
    OSSL() { docker run --rm -v "$WORK:/work" -w /work "$OSSL_IMAGE" "$@"; }
    OSSL=docker
else
    echo "verify_msix: neither osslsigncode nor docker available" >&2
    exit 3
fi

echo "==> building signed sample MSIX"
(cd "$ROOT" && go run ./internal/gensignedmsix "$WORK")
[ -f "$WORK/signed.msix" ] || fail "signed.msix not produced"

echo "==> osslsigncode verify (recomputes the APPX digests)"
OSSL verify -in signed.msix -CAfile signer.pem | tee "$WORK/sigverify.txt" || true

grep -q 'Signature verification: ok' "$WORK/sigverify.txt" \
    || fail "osslsigncode did not verify the signed MSIX"
grep -q 'Succeeded' "$WORK/sigverify.txt" || fail "osslsigncode overall result not Succeeded"

# All four digest comparison blocks must be present and each pair must match.
for section in 'Block Map' 'Content Types' 'Data' 'Central Directory'; do
    grep -q "Checking $section hashes" "$WORK/sigverify.txt" \
        || fail "$section digest comparison missing (osslsigncode too old, or APPX digests not checked — do NOT trust a bare Succeeded)"
    cur=$(grep -A2 "Checking $section hashes" "$WORK/sigverify.txt" | grep 'Current message digest' | grep -oE '[0-9A-Fa-f]{64}')
    calc=$(grep -A3 "Checking $section hashes" "$WORK/sigverify.txt" | grep 'Calculated message digest' | grep -oE '[0-9A-Fa-f]{64}')
    [ -n "$cur" ] && [ "$cur" = "$calc" ] || fail "$section digest mismatch (current=$cur calculated=$calc)"
    echo "    $section digest match: $cur"
done

echo "==> tamper test (one flipped payload byte must fail verification)"
python3 - "$WORK/signed.msix" "$WORK/tampered.msix" <<'EOF'
import sys
data = bytearray(open(sys.argv[1], 'rb').read())
data[100] ^= 0xFF  # inside the first local file record's data, not the signature
open(sys.argv[2], 'wb').write(bytes(data))
EOF
if OSSL verify -in tampered.msix -CAfile signer.pem > "$WORK/tamperverify.txt" 2>&1; then
    fail "tampered package unexpectedly verified"
fi
grep -q 'Failed' "$WORK/tamperverify.txt" || fail "tampered package did not report Failed"
echo "    tampered package rejected"

echo "verify_msix: ALL CHECKS PASSED"
