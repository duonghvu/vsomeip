# DTLS UDP simulation (standalone)

Two executables that exercise the new `dtls_session` + `dtls_backend_openssl`
code paths end-to-end against a real DTLS 1.2 stack (OpenSSL 3.0+).

The simulation is intentionally standalone: it does **not** link
`libvsomeip3`. That keeps it buildable on developer machines (Linux, macOS,
QNX hosts) without porting the full vSomeIP library to those targets. The
DTLS code under test is identical to what `dtls_udp_server_endpoint_impl`
and `dtls_udp_client_endpoint_impl` use inside `libvsomeip3` on Linux/QNX.

## What it verifies

- `dtls::backend::create_default()` returns a working OpenSSL 3 backend.
- `dtls::session` drives the DTLS 1.2 handshake to completion, including
  HelloVerifyRequest cookie exchange (DoS mitigation).
- Mutual authentication works (both client and server present certificates
  signed by a shared test CA; both verify the peer chain).
- Application data flows in both directions through encrypted records.
- Graceful shutdown (`close_notify`) is observed and handled.

The cipher suite tested is the project default: `ECDHE-ECDSA-AES128-GCM-SHA256`.

## Build

```bash
cd examples/dtls_simulation
cmake -B build -S . -DOPENSSL_ROOT_DIR=$(brew --prefix openssl@3)
cmake --build build -j
```

On Linux, drop `-DOPENSSL_ROOT_DIR` if OpenSSL 3 is in the default search path.

## Run

```bash
# 1. Generate a one-shot test CA + server cert + client cert.
OPENSSL_BIN=$(brew --prefix openssl@3)/bin/openssl ./gen_test_certs.sh ./certs

# 2. Start the server (binds 127.0.0.1:32444 by default).
./build/dtls_server_node \
    --cert certs/server.pem --key certs/server.key --ca certs/ca.pem &

# 3. Run the client (sends 3 ping payloads, expects 3 pong replies).
./build/dtls_client_node \
    --cert certs/client.pem --key certs/client.key --ca certs/ca.pem \
    --count 3
```

A successful run prints `[client] PASS (received 3/3)` and exits 0. The
server log shows the cookie-exchange round-trip, then handshake completion,
then three encrypted plaintext exchanges.

## Cert hygiene

`gen_test_certs.sh` produces self-signed test material only. **Never use the
generated keys in production.** Production deployments must source
certificates and private keys from the integration team's PKI; the library
loads them via the JSON `dtls.certificate`, `dtls.private_key`, and
`dtls.ca_bundle` keys (see `documentation/vsomeipDtlsUserGuide.md`).
