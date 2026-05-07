#!/usr/bin/env bash
# Copyright (C) 2014-2026 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

# Generates a self-signed CA + server cert + client cert for the DTLS
# simulation. Test only — never use these for production.

set -euo pipefail

OUT="${1:-./certs}"
mkdir -p "$OUT"
cd "$OUT"

# Use the OpenSSL 3 binary explicitly so we don't accidentally hit a system
# libressl/openssl 1.1 that lacks DTLS 1.2 ECDHE-ECDSA support.
OPENSSL_BIN="${OPENSSL_BIN:-openssl}"

CURVE="prime256v1"

echo "[*] generating CA"
"$OPENSSL_BIN" ecparam -name "$CURVE" -genkey -noout -out ca.key
"$OPENSSL_BIN" req -x509 -new -key ca.key -days 365 -out ca.pem \
    -subj "/CN=vsomeip-dtls-test-ca"

gen_leaf() {
    local name="$1"
    echo "[*] generating $name cert"
    "$OPENSSL_BIN" ecparam -name "$CURVE" -genkey -noout -out "${name}.key"
    "$OPENSSL_BIN" req -new -key "${name}.key" -out "${name}.csr" \
        -subj "/CN=${name}.vsomeip.test"
    "$OPENSSL_BIN" x509 -req -in "${name}.csr" -CA ca.pem -CAkey ca.key \
        -CAcreateserial -out "${name}.pem" -days 365
    rm -f "${name}.csr"
}

gen_leaf server
gen_leaf client

echo
echo "[+] wrote certs into $(pwd)"
ls -1 *.pem *.key
