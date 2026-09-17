### vSomeIP

##### Copyright
Copyright (C) 2014-2026 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
This Source Code Form is subject to the terms of the Mozilla Public
License, v. 2.0. If a copy of the MPL was not distributed with this
file, You can obtain one at http://mozilla.org/MPL/2.0/.

##### License

This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
If a copy of the MPL was not distributed with this file, You can obtain one at http://mozilla.org/MPL/2.0/.

##### Contributing Guidelines

For comprehensive details on how to contribute effectively to the project, please refer to our [CONTRIBUTING.md](./CONTRIBUTING.md) file.

##### vSomeIP Overview
----------------
The vSomeIP stack implements the http://some-ip.com/ (Scalable service-Oriented MiddlewarE over IP (SOME/IP)) Protocol.
The stack consists out of:

* a shared library for SOME/IP (`libvsomeip3.so`)
* a shared library for SOME/IP's configuration module (`libvsomeip3-cfg.so`)
* a shared library for SOME/IP's service discovery (`libvsomeip3-sd.so`)
* a shared library for SOME/IP's E2E protection module (`libvsomeip3-e2e.so`)

##### DTLS 1.2 over UDP (experimental, branch `test/dtls-udp`)

> **Status: experimental, not for production.** The crypto core (OpenSSL 3 backend and per-peer session) passes a standalone round-trip simulation. The DTLS endpoint classes do not compile yet with `-DENABLE_DTLS=ON`, the configuration/factory/routing wiring is not done, and there are known security defects (see the summary, §7). Feedback and testing are welcome.

This branch adds opt-in DTLS 1.2 protection for unicast SOME/IP over UDP. A service enables it through configuration; application code does not change. SOME/IP-SD multicast stays plaintext.

###### Documents

| Document | Contents |
|---|---|
| [documentation/dtls/vsomeip_DTLS_Summary.pdf](documentation/dtls/vsomeip_DTLS_Summary.pdf) ([HTML](documentation/dtls/vsomeip_DTLS_Summary.html)) | Architecture, software file structure, verification approach, known issues, how to give feedback |
| [documentation/dtls/vsomeip_DTLS_Requirements_Specification.pdf](documentation/dtls/vsomeip_DTLS_Requirements_Specification.pdf) ([HTML](documentation/dtls/vsomeip_DTLS_Requirements_Specification.html)) | System and software requirements with status, architecture decisions, implementation steps, open issues |
| [DTLS_TESTING.md](DTLS_TESTING.md) | Step-by-step test guide for Ubuntu |
| [examples/dtls_simulation/readme.md](examples/dtls_simulation/readme.md) | Standalone DTLS round-trip simulation |

###### Quick start

Standalone simulation (Linux or macOS, needs OpenSSL 3 and Boost.Asio; it does not build `libvsomeip3`):

```bash
cd examples/dtls_simulation
./run_simulation.sh --count 5     # expect "DTLS simulation: PASS"
```

Library build (Linux). DTLS is off by default:

```bash
cmake -Bbuild -DENABLE_DTLS=OFF -DGTEST_ROOT=/usr/src/googletest .   # must behave like upstream
cmake --build build --target build_tests
ctest --test-dir build -R '^unit_' --output-on-failure

cmake -Bbuild-dtls -DENABLE_DTLS=ON .    # requires OpenSSL >= 3.0 (3.5 LTS recommended)
```

###### Configuration

```json
"dtls": {
    "enable": "true",
    "certificate": "/etc/vsomeip/ecu.pem",
    "private_key": "/etc/vsomeip/ecu.key",
    "ca_bundle": "/etc/vsomeip/ca.pem",
    "verify_peer": "true",
    "cookie_exchange": "true"
},
"services": [
    { "service": "0x2444", "instance": "0x0001", "unreliable_secure": "32444" }
]
```

All keys and defaults are listed in Annex A of the requirements specification. Never use the certificates produced by `gen_test_certs.sh` outside tests.

###### Development guidelines

* **Separate classes.** DTLS lives in `dtls_*` files. Do not modify `udp_server_endpoint_impl.*`, `udp_client_endpoint_impl.*` or `implementation/service_discovery/*`.
* **One crypto boundary.** Only `dtls_backend_openssl.cpp` includes OpenSSL; everything else uses `dtls::backend`.
* **Compile-time switch.** Guard all DTLS code with `VSOMEIP_HAS_DTLS` (set by `-DENABLE_DTLS=ON`). With the option OFF the library must behave like upstream.
* **Errors.** Crypto failures return `dtls::result_e` and are logged with `VSOMEIP_ERROR`; never throw across endpoint boundaries. Never log keys, secrets or decrypted payloads.
* **Resources.** Get sockets and timers from `abstract_socket_factory`; capture `weak_ptr` in session callbacks; bound per-peer state before a handshake completes.
* **Style.** Follow [CONTRIBUTING.md](./CONTRIBUTING.md) (clang-format pre-commit hook, `_argument`, `member_`). New files carry the MPL-2.0 header.
* **Tests.** Name unit tests `unit_dtls_*` so the CI filter `^unit_` runs them. Link each test to a requirement ID (`SWR-DTLS-nnn`).
* **Commits.** `dtls(udp): <what>`, one logical change per commit, with `Implements:` / `Verified-by:` lines naming requirement and test IDs.

###### Testing levels

| Level | Scope | Location |
|---|---|---|
| Unit | Backend, session, config parser; in-memory, no sockets | `test/unit_tests/dtls_tests/` (planned) |
| Component | One DTLS endpoint with fake sockets | `test/unit_tests/endpoint_tests/` |
| Integration | Several ECUs in one process with fault injection, hybrid mode | `test/network_tests/fake_socket_tests/` |
| Qualification | Real processes on two containers, `openssl s_client`/`s_server` interop, stress, DTLS ON and OFF | `test/network_tests/dtls_tests/` (planned), `zuul/network-tests` |

###### Feedback and community review

Reports from other platforms are the most useful help right now. Please include OS, compiler, Boost version, OpenSSL version (`openssl version`), the exact command, the result, and the logs (`examples/dtls_simulation/build/*.log`).

* **Issues on this fork**: [duonghvu/vsomeip issues](https://github.com/duonghvu/vsomeip/issues) for problems with this branch.
* **Design discussion with the vsomeip community**: [COVESA/vsomeip Discussions](https://github.com/COVESA/vsomeip/discussions). Link this branch and the two PDFs, and ask the open questions from §8 of the requirements specification.
* **Community call**: COVESA holds a monthly vsomeip meeting; ask for an agenda slot through the [COVESA wiki](https://wiki.covesa.global/display/WIK4/VSOMEIP+Meeting+Notes).
* **Upstream contribution**: only after the known issues are fixed and tests are green, as a series of small pull requests against `COVESA/vsomeip:master`. Do not open issues on COVESA/vsomeip for this experimental branch.

##### Build Instructions for Linux

###### Dependencies

- A C++20 enabled compiler is needed.
- vSomeIP uses CMake as buildsystem.
- vSomeIP uses Boost >= 1.75.0:

For the tests Google's test framework https://code.google.com/p/googletest/[gtest] is needed.
-- URL: https://googletest.googlecode.com/files/gtest-<version>.zip

To build the documentation doxygen and graphviz are needed:
--`sudo apt-get install doxygen graphviz`

###### Compilation

For compilation call:

```bash
mkdir build
cd build
cmake ..
make
```

To specify a installation directory (like `--prefix=` if you're used to autotools) call cmake like:
```bash
cmake -DCMAKE_INSTALL_PREFIX:PATH=$YOUR_PATH ..
make
make install
```

###### Compilation with predefined unicast and/or diagnosis address
To predefine the unicast address, call cmake like:
```bash
cmake -DUNICAST_ADDRESS=<YOUR IP ADDRESS> ..
```

To predefine the diagnosis address, call cmake like:
```bash
cmake -DDIAGNOSIS_ADDRESS=<YOUR DIAGNOSIS ADDRESS> ..
```
The diagnosis address is a single byte value.

###### Compilation with custom default configuration folder
To change the default configuration folder, call cmake like:
```bash
cmake -DDEFAULT_CONFIGURATION_FOLDER=<DEFAULT CONFIGURATION FOLDER> ..
```
The default configuration folder is `/etc/vsomeip`.

###### Compilation with custom default configuration file
To change the default configuration file, call cmake like:
```bash
cmake -DDEFAULT_CONFIGURATION_FILE=<DEFAULT CONFIGURATION FILE> ..
```
The default configuration file is `/etc/vsomeip.json`.

###### Compilation with signal handling

To compile vSomeIP with signal handling (SIGINT/SIGTERM) enabled, call cmake like:
```bash
cmake -DENABLE_SIGNAL_HANDLING=1 ..
```
In the default setting, the application has to take care of shutting down vSomeIP in case these signals are received.


##### Build Instructions for Android

###### Dependencies

- vSomeIP uses Boost >= 1.75. The boost libraries (system and filesystem) must be included in the Android source tree and integrated into the build process with an appropriate Android.bp file.

###### Compilation

In general for building the Android source tree the instructions found on the pages from the Android Open Source Project (AOSP) apply (https://source.android.com/setup/build/requirements).

To integrate the vSomeIP library into the build process, the source code together with the Android.bp file has to be inserted into the Android source tree (by simply copying or by fetching with a custom platform manifest).
When building the Android source tree, the Android.bp file is automatically found and considered by the build system.

In order that the vSomeIP library is also included in the Android image, the library has to be added to the PRODUCT_PACKAGES variable in one of a device/target specific makefile:

```
PRODUCT_PACKAGES += \
    libvsomeip \
    libvsomeip_cfg \
    libvsomeip_sd \
    libvsomeip_e2e \
```

##### Build Instructions for Windows

###### Setup

- Visual Studio Code
- Visual Studio Build Tools with:
    - Desktop development with C++
    - MSVC v143 - VS 2022 C++ x64/x86 build tools
    - Windows 10/11 SDK
    - CMake for Windows
- vSomeIP uses CMake as buildsystem.
- vSomeIP uses Boost >= 1.75.0:
- GIT

For the tests Google's test framework https://code.google.com/p/googletest/[gtest] is needed.
-- URL: https://googletest.googlecode.com/files/gtest-<version>.zip
or
-- git clone https://github.com/google/googletest.git

###### Compilation

For compilation call:

```bash
rmdir /s /q build
cd build
cmake .. -A x64 -DCMAKE_INSTALL_PREFIX:PATH=$YOUR_PATH
cmake --build . --config [Release|Debug]
cmake --build . --config [Release|Debug] --target install
```

For compilation outside vsomeip-lib folder call:

```bash
rmdir /s /q build
cmake -B "buildlib" -DCMAKE_BUILD_TYPE=[Release|Debug] -DCMAKE_INSTALL_PREFIX=$YOUR_PATH -A x64 vsomeip-lib
#vsomeip-lib compilation
cmake --build build --config [Release|Debug] --parallel 16 --target install
#examples compilation
cmake --build build --config [Release|Debug] --parallel 16 --parallel 16 --target examples
cmake --build build --config [Release|Debug] --parallel 16 --target install
#unit-tests compilation
cmake --build build/test --config [Release|Debug] --parallel 16 --parallel 16 --target build_unit_tests
#all tests compilation
cmake --build build/test --config [Release|Debug] --parallel 16 --parallel 16 --target all build_tests
```
