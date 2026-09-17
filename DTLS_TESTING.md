# DTLS over UDP — Testing Guide (Ubuntu)

This branch (`feature/dtls-udp`) adds native DTLS 1.2 over UDP support to
vsomeip 3.7.2 using OpenSSL 3.0+. This document is the operator-facing
guide for verifying the work on a stock Ubuntu machine.

For the design rationale see [`vsomeip_DTLS_UDP_3_7_2_Plan.md`](../vsomeip_DTLS_UDP_3_7_2_Plan.md);
for the standalone simulation see [`examples/dtls_simulation/readme.md`](examples/dtls_simulation/readme.md).

---

## 1. Prerequisites (Ubuntu 22.04 LTS or newer)

```bash
sudo apt-get update
sudo apt-get install -y \
    git build-essential cmake pkg-config \
    libboost-system-dev libboost-filesystem-dev \
    libssl-dev openssl \
    libgtest-dev   # optional, only for the in-tree test suite
```

Verify the OpenSSL version is 3.0 or newer:

```bash
openssl version          # expect: OpenSSL 3.x.y
pkg-config --modversion openssl   # same
```

If you are on an older Ubuntu where `libssl-dev` is still 1.1.1, build
OpenSSL 3 from source or use a backport — the DTLS code refuses to compile
against pre-3.0 (compile-time `#error` in `dtls_backend_openssl.cpp`).

---

## 2. Pull the branch

```bash
git clone https://github.com/duonghvu/vsomeip.git
cd vsomeip
git checkout feature/dtls-udp
```

Confirm:

```bash
git log --oneline -1     # expect a commit on top of vsomeip 3.7.2
git diff --stat 3.7.2..HEAD | tail
```

You should see one modified file (`CMakeLists.txt`) and a set of new files
under `implementation/endpoints/`, `implementation/configuration/`, and
`examples/dtls_simulation/`.

---

## 3. Build the standalone DTLS round-trip simulation (fast path)

This builds **only** the DTLS code and two simulator nodes — it does NOT
build `libvsomeip3` itself. Use it to verify the DTLS data path end-to-end
in under a minute. No `sudo`, no `/etc/vsomeip` needed.

```bash
cd examples/dtls_simulation
cmake -B build -S .
cmake --build build -j$(nproc)
./gen_test_certs.sh ./certs        # creates a one-shot test CA + 2 leaf certs
```

You should now have:

```
build/dtls_server_node
build/dtls_client_node
certs/{ca,server,client}.{pem,key}
```

### 3.1. Run the round-trip

In one terminal:

```bash
./build/dtls_server_node \
    --cert certs/server.pem --key certs/server.key --ca certs/ca.pem \
    --bind 127.0.0.1 --port 32444
```

In a second terminal:

```bash
./build/dtls_client_node \
    --cert certs/client.pem --key certs/client.key --ca certs/ca.pem \
    --server 127.0.0.1 --port 32444 --count 5
```

A successful run prints `[client] PASS (received 5/5)` and exits 0.

### 3.2. One-shot scripted run (with visualization)

The repo includes a one-shot runner that captures both logs and renders a
visual summary:

```bash
./run_simulation.sh             # build + run + render
```

Outputs (in `examples/dtls_simulation/build/`):

| File | Contents |
|---|---|
| `server.log` | Full server-side trace (handshake + ciphertext I/O + plaintext rx) |
| `client.log` | Full client-side trace |
| `result.txt` | Side-by-side ASCII timeline (handshake → data → close_notify) |
| `result.svg` | SVG sequence diagram of the same run, viewable in any browser |

Open `result.svg` in a browser (`xdg-open result.svg`) for the visual.

### 3.3. What "PASS" actually proves

| Layer | What is exercised |
|---|---|
| Crypto context | OpenSSL 3 `DTLS_*_method`, ECDSA cert + key load, CA verify chain, cipher pin |
| Handshake | Full DTLS 1.2 with HelloVerifyRequest cookie exchange (DoS mitigation) |
| Mutual auth | Both peers present a cert; both verify it against the shared CA |
| Data path | Plaintext encrypt → UDP → decrypt round-trip in both directions |
| Shutdown | Graceful `close_notify`, observed by the peer |

The same `dtls_session` and `dtls_backend_openssl` code is what the in-tree
`dtls_udp_server_endpoint_impl` and `dtls_udp_client_endpoint_impl` use
inside `libvsomeip3` — so a green simulation is meaningful evidence that the
cryptographic layer is correct.

---

## 4. Build the full library (production path)

Use this on a Linux host (Ubuntu/QNX/Android-target). The vsomeip Linux
build relies on GNU-ld–specific link flags (`-Wl,-wrap`) and `librt`, so
this section will not work on macOS or *BSD without porting work.

```bash
cd <repo root>
cmake -B build -S . \
    -DCMAKE_BUILD_TYPE=Debug \
    -DENABLE_DTLS=ON \
    -DENABLE_SIGNAL_HANDLING=1
cmake --build build -j$(nproc)
```

To verify the OFF path is bit-identical to vanilla 3.7.2:

```bash
cmake -B build-off -S . -DENABLE_DTLS=OFF -DCMAKE_BUILD_TYPE=Debug
cmake --build build-off -j$(nproc)
```

Run the test suite (the existing tests should be green; DTLS-specific tests
will be added in Phase 7 of the plan):

```bash
ctest --test-dir build --output-on-failure
ctest --test-dir build -R dtls --output-on-failure   # DTLS-only subset
```

### 4.1. Run a DTLS-protected hello_world (end-to-end inside libvsomeip3)

Once the full library builds and the configuration plumbing in
`endpoint_manager_impl` / `routing_manager_impl` / `configuration_impl` is
wired in (plan Phase 6 — TODO on this branch, see §6 below):

```bash
sudo cp examples/dtls_simulation/certs/{ca,server}.pem /etc/vsomeip/
sudo cp examples/dtls_simulation/certs/server.key      /etc/vsomeip/
# Use a JSON config containing the new "dtls" block (see plan §8).
VSOMEIP_CONFIGURATION=./helloworld-dtls.json \
    ./build/examples/hello_world/hello_world_service &
VSOMEIP_CONFIGURATION=./helloworld-dtls.json \
    ./build/examples/hello_world/hello_world_client
```

---

## 5. Production gate (what must be green before this lands on `master`)

| Gate | How to verify | Owner |
|---|---|---|
| `cmake -DENABLE_DTLS=ON` builds clean on Ubuntu 22.04 + GCC 11 | CI job | Build infra |
| `cmake -DENABLE_DTLS=OFF` builds bit-identical to vanilla 3.7.2 | `sha256sum libvsomeip3.so` against tag | Build infra |
| `ctest -R dtls` passes | CI job | DTLS author |
| `ctest` (full suite) passes with DTLS=ON | CI job | DTLS author |
| Static analysis (clang-tidy, clang-format) clean | Pre-commit hook + CI | DTLS author |
| MISRA C++ baseline not regressed | Project's static-analysis pipeline | Integration team |
| Path-MTU stress on real automotive Ethernet | Bench rig | Integration team |
| Cert revocation (CRL/OCSP-stub) test passes | Bench rig | Integration team |
| 1000-iteration handshake stress green | Standalone test | DTLS author |
| User docs updated (`vsomeipUserGuide.md`, `vsomeipConfiguration.md`, `vsomeipDtlsUserGuide.md`) | Doc review | DTLS author |
| No `supplier`/`ADCU`/`CVC`-specific language in any source/doc | `grep -rniE 'supplier\|adcu\|cvc'` returns empty | Reviewer |

The current branch satisfies the first three rows for the **standalone
simulation** but not yet for the full library: factory wiring in
`endpoint_manager_impl` and the JSON parser in `configuration_impl` are
still skeleton-only. See §6.

---

## 6. Open work before COVESA upstream PR

The plan lays out seven phases. This branch ships the foundational pieces
(crypto backend, DTLS session, endpoint sibling skeletons, CMake option,
configuration struct + parser, standalone simulation). The remaining work
to be a clean COVESA-mainstream PR:

1. **Wire `endpoint_manager_impl::find_or_create_server_endpoint`** to
   instantiate `dtls_udp_server_endpoint_impl` when a service has
   `unreliable_secure` configured. Mirrors the existing UDP branch.
2. **Wire `routing_manager_impl`** to tag `serviceinfo` during the new
   3.7.2 preparation stage when DTLS is configured.
3. **Wire `configuration_impl::load_service` and a new `load_dtls`** to
   parse the JSON `dtls` block (already implemented in
   `dtls_configuration::load`) and expose getters.
4. **Add `examples/hello_world_dtls/`** mirroring `examples/hello_world` so
   integrators can confirm the end-to-end path with no application-code
   change.
5. **Add `test/network_tests/dtls_tests/`** ctest-driven negative tests:
   wrong CA, expired cert, MTU > path-MTU, 1000-iteration handshake
   stress, hybrid-mode interaction.
6. **User guide** (`documentation/vsomeipDtlsUserGuide.md`) — JSON keys,
   cipher recommendations, key-management responsibilities, hybrid-mode
   notes (per ADR-006).
7. **CI**: extend the project's GitHub Actions workflow to run the build
   matrix `[ENABLE_DTLS=ON, ENABLE_DTLS=OFF]` on `ubuntu-22.04` and
   `ubuntu-24.04`.

Items 1–3 are mechanical edits constrained by the file inventory in plan
§4.2. Items 4–5 are additive. Item 6 is documentation only. Item 7 is CI.

---

## 7. Submitting upstream to COVESA/vsomeip

When the gates in §5 are green:

1. Sign the COVESA CLA: <https://covesa.global/contributor-license-agreement/>.
2. Verify pre-commit hook is installed (per `CONTRIBUTING.md` §"How to use
   Clang Format"):
   ```bash
   pip install pre-commit && pre-commit install
   ```
3. Rebase the branch onto upstream `master`:
   ```bash
   git remote add upstream https://github.com/COVESA/vsomeip.git
   git fetch upstream
   git rebase upstream/master
   ```
4. Run the full gate locally (§5) once more after the rebase.
5. Open the PR against `COVESA/vsomeip:master` from
   `duonghvu/vsomeip:feature/dtls-udp`. Title: `dtls(udp): native DTLS 1.2
   over UDP support`. Description should link this guide and the plan
   document, list the ADRs (plan §3), and include the CI matrix evidence
   from §5.
6. Address review feedback in additional commits (do **not** force-push
   during review — COVESA reviewers prefer to see the diff per round).
   After approval, the maintainer typically squash-merges.
