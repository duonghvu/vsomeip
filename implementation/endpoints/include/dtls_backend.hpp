// Copyright (C) 2014-2026 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#pragma once

#ifdef VSOMEIP_HAS_DTLS

#include <chrono>
#include <cstdint>
#include <memory>
#include <string>

namespace vsomeip_v3 {
namespace dtls {

// Result codes propagated out of the crypto backend. Crypto errors never throw
// across endpoint boundaries; they are translated to one of these enumerators
// and logged via VSOMEIP_ERROR by the caller (ADR-002).
enum class result_e : std::uint8_t {
    ok,
    want_read,
    want_write,
    handshake_in_progress,
    handshake_failed,
    peer_closed,
    fatal,
};

// Configuration for a DTLS endpoint context. All paths are PEM files. The
// values come straight from the JSON `dtls` block parsed by configuration_impl.
struct context_config {
    std::string version_ {"1.2"};
    std::string cipher_list_ {"ECDHE-ECDSA-AES128-GCM-SHA256"};
    std::string certificate_ {};
    std::string private_key_ {};
    std::string ca_bundle_ {};
    bool verify_peer_ {true};
    bool cookie_exchange_ {true};
    std::chrono::milliseconds handshake_timeout_ {5000};
};

// Opaque per-context handle. The OpenSSL backend wraps SSL_CTX*; alternative
// backends (mbedTLS, HSM-backed) keep their own state behind this same shape.
class context {
public:
    virtual ~context() = default;
    virtual bool valid() const = 0;
    virtual const std::string& last_error() const = 0;
};

// Per-peer DTLS session, owned by a dtls_session above this layer.
class session_state {
public:
    virtual ~session_state() = default;
    virtual result_e do_handshake() = 0;
    virtual result_e read(std::uint8_t* _out, std::size_t _max, std::size_t& _read) = 0;
    virtual result_e write(const std::uint8_t* _in, std::size_t _len, std::size_t& _written) = 0;
    virtual result_e shutdown() = 0;
    // Inject ciphertext arriving over the underlying UDP socket.
    virtual void feed(const std::uint8_t* _data, std::size_t _len) = 0;
    // Drain ciphertext the backend wants to send out over the underlying UDP
    // socket. Returns 0 if nothing pending. Caller passes through Boost.Asio.
    virtual std::size_t drain(std::uint8_t* _out, std::size_t _max) = 0;
    virtual bool handshake_done() const = 0;
    virtual std::chrono::milliseconds next_timeout() const = 0;
    // Notify the backend that the dtls_session retransmit timer fired so it
    // can re-send pending handshake records. Maps to OpenSSL's
    // DTLSv1_handle_timeout(); a no-op once the handshake has completed.
    virtual void handle_timeout() = 0;
    // Returns the most recent backend-internal error string (cleared after
    // each call). Used by the endpoint to enrich VSOMEIP_ERROR log lines.
    virtual std::string take_last_error() = 0;
};

// Backend factory. The concrete implementation lives in dtls_backend_openssl.cpp.
// Replacing the backend (mbedTLS, HSM) means swapping this single .cpp out
// without touching endpoints (ADR-002).
class backend {
public:
    virtual ~backend() = default;

    virtual std::shared_ptr<context> create_server_context(const context_config& _cfg) = 0;
    virtual std::shared_ptr<context> create_client_context(const context_config& _cfg) = 0;

    virtual std::unique_ptr<session_state> create_server_session(const std::shared_ptr<context>& _ctx) = 0;
    virtual std::unique_ptr<session_state> create_client_session(const std::shared_ptr<context>& _ctx) = 0;

    static std::shared_ptr<backend> create_default();
};

} // namespace dtls
} // namespace vsomeip_v3

#endif // VSOMEIP_HAS_DTLS
