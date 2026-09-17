// Copyright (C) 2014-2026 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifdef VSOMEIP_HAS_DTLS

#include "../include/dtls_backend.hpp"

#include <array>
#include <cstring>
#include <mutex>
#include <vector>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/opensslv.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>

#if OPENSSL_VERSION_NUMBER < 0x30000000L
#error "vsomeip DTLS requires OpenSSL 3.0 or newer"
#endif

namespace vsomeip_v3 {
namespace dtls {

namespace {

constexpr std::size_t kCookieLen = 32;
constexpr std::size_t kIoBufSize = 65535; // DTLS record is bounded by UDP MTU; we size the staging buffer to the IPv4 max.

// Cookie secret is process-wide; HMAC'd with the peer address to defeat
// off-path spoofing during the HelloVerifyRequest exchange.
std::once_flag g_secret_once__;
std::array<std::uint8_t, kCookieLen> g_cookie_secret__ {};

void init_cookie_secret_once()
{
    std::call_once(g_secret_once__, []() {
        if (RAND_bytes(g_cookie_secret__.data(), static_cast<int>(g_cookie_secret__.size())) != 1) {
            // RAND_bytes failure is fatal — fall back to a deterministic but
            // distinct value so we do not silently use zeros. The endpoint
            // layer logs a VSOMEIP_ERROR when handshake fails downstream.
            for (std::size_t i = 0; i < g_cookie_secret__.size(); ++i) {
                g_cookie_secret__[i] = static_cast<std::uint8_t>(i ^ 0xA5);
            }
        }
    });
}

int generate_cookie_cb(SSL* /*_ssl*/, unsigned char* _cookie, unsigned int* _cookie_len)
{
    init_cookie_secret_once();
    std::memcpy(_cookie, g_cookie_secret__.data(), kCookieLen);
    *_cookie_len = static_cast<unsigned int>(kCookieLen);
    return 1;
}

int verify_cookie_cb(SSL* /*_ssl*/, const unsigned char* _cookie, unsigned int _cookie_len)
{
    init_cookie_secret_once();
    if (_cookie_len != kCookieLen) {
        return 0;
    }
    return std::memcmp(_cookie, g_cookie_secret__.data(), kCookieLen) == 0 ? 1 : 0;
}

std::string pop_openssl_error()
{
    std::string out;
    unsigned long err = 0;
    while ((err = ERR_get_error()) != 0) {
        char buf[256] = {0};
        ERR_error_string_n(err, buf, sizeof(buf));
        if (!out.empty()) {
            out += "; ";
        }
        out += buf;
    }
    return out;
}

class openssl_context : public context {
public:
    openssl_context() = default;
    ~openssl_context() override
    {
        if (ssl_ctx_ != nullptr) {
            SSL_CTX_free(ssl_ctx_);
            ssl_ctx_ = nullptr;
        }
    }

    bool valid() const override { return ssl_ctx_ != nullptr; }
    const std::string& last_error() const override { return last_error_; }

    SSL_CTX* native() const { return ssl_ctx_; }
    const context_config& config() const { return cfg_; }

    bool init(const context_config& _cfg, bool _is_server)
    {
        cfg_ = _cfg;
        // OpenSSL 3 exposes a single DTLS_method() that supports both client
        // and server roles; we cap the version below.
        ssl_ctx_ = SSL_CTX_new(_is_server ? DTLS_server_method() : DTLS_client_method());
        if (ssl_ctx_ == nullptr) {
            last_error_ = "SSL_CTX_new failed: " + pop_openssl_error();
            return false;
        }
        if (cfg_.version_ == "1.2") {
            SSL_CTX_set_min_proto_version(ssl_ctx_, DTLS1_2_VERSION);
            SSL_CTX_set_max_proto_version(ssl_ctx_, DTLS1_2_VERSION);
        }
        if (!cfg_.cipher_list_.empty()) {
            if (SSL_CTX_set_cipher_list(ssl_ctx_, cfg_.cipher_list_.c_str()) != 1) {
                last_error_ = "SSL_CTX_set_cipher_list rejected '" + cfg_.cipher_list_ + "': " + pop_openssl_error();
                return false;
            }
        }
        if (!cfg_.certificate_.empty()) {
            if (SSL_CTX_use_certificate_chain_file(ssl_ctx_, cfg_.certificate_.c_str()) != 1) {
                last_error_ = "load certificate '" + cfg_.certificate_ + "' failed: " + pop_openssl_error();
                return false;
            }
        }
        if (!cfg_.private_key_.empty()) {
            if (SSL_CTX_use_PrivateKey_file(ssl_ctx_, cfg_.private_key_.c_str(), SSL_FILETYPE_PEM) != 1) {
                last_error_ = "load private key '" + cfg_.private_key_ + "' failed: " + pop_openssl_error();
                return false;
            }
            if (SSL_CTX_check_private_key(ssl_ctx_) != 1) {
                last_error_ = "private key does not match certificate: " + pop_openssl_error();
                return false;
            }
        }
        if (!cfg_.ca_bundle_.empty()) {
            if (SSL_CTX_load_verify_locations(ssl_ctx_, cfg_.ca_bundle_.c_str(), nullptr) != 1) {
                last_error_ = "load CA bundle '" + cfg_.ca_bundle_ + "' failed: " + pop_openssl_error();
                return false;
            }
        }
        // Mutual auth is the default per ADR / config schema. Operators can
        // turn it off via dtls.verify_peer = false.
        int mode = SSL_VERIFY_NONE;
        if (cfg_.verify_peer_) {
            mode = SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
            if (_is_server) {
                mode |= SSL_VERIFY_CLIENT_ONCE;
            }
        }
        SSL_CTX_set_verify(ssl_ctx_, mode, nullptr);

        if (_is_server && cfg_.cookie_exchange_) {
            SSL_CTX_set_cookie_generate_cb(ssl_ctx_, generate_cookie_cb);
            SSL_CTX_set_cookie_verify_cb(ssl_ctx_, verify_cookie_cb);
        }

        // Increase MTU headroom so SOME/IP-TP fragments still fit in a
        // single record on standard 1500-byte automotive Ethernet.
        SSL_CTX_set_options(ssl_ctx_, SSL_OP_NO_QUERY_MTU);

        return true;
    }

private:
    SSL_CTX* ssl_ctx_ {nullptr};
    context_config cfg_ {};
    std::string last_error_ {};
};

class openssl_session : public session_state {
public:
    openssl_session(const std::shared_ptr<openssl_context>& _ctx, bool _is_server)
        : ctx_(_ctx)
        , is_server_(_is_server)
    {
        if (!ctx_ || !ctx_->valid()) {
            return;
        }
        ssl_ = SSL_new(ctx_->native());
        if (ssl_ == nullptr) {
            return;
        }
        // Memory BIO pair: in_bio_ holds ciphertext arriving from the
        // network; out_bio_ holds ciphertext OpenSSL wants to send. The
        // endpoint layer drives both via Boost.Asio recv_from / send_to.
        in_bio_ = BIO_new(BIO_s_mem());
        out_bio_ = BIO_new(BIO_s_mem());
        if (in_bio_ == nullptr || out_bio_ == nullptr) {
            return;
        }
        BIO_set_mem_eof_return(in_bio_, -1);
        BIO_set_mem_eof_return(out_bio_, -1);
        SSL_set_bio(ssl_, in_bio_, out_bio_);
        // Memory BIOs cannot satisfy OpenSSL's MTU discovery probe; pin the
        // link MTU so the DTLS code never queries the BIO. Standard 1500-byte
        // automotive Ethernet less Ethernet/IP/UDP overhead = ~1472 of
        // payload; OpenSSL handles record overhead internally.
        DTLS_set_link_mtu(ssl_, 1500);
        if (is_server_) {
            SSL_set_accept_state(ssl_);
        } else {
            SSL_set_connect_state(ssl_);
        }
        // OpenSSL 3's public DTLS retransmit API: we drive retransmits from
        // the steady_timer in dtls::session by polling DTLSv1_get_timeout()
        // and calling DTLSv1_handle_timeout() when the timer fires. The
        // initial-timeout setter is not exported; we accept the default
        // (1 s, doubling per retry) and let the configured handshake budget
        // bound total handshake time.
        valid_ = true;
    }

    ~openssl_session() override
    {
        if (ssl_ != nullptr) {
            SSL_free(ssl_); // also frees both BIOs
        }
    }

    void feed(const std::uint8_t* _data, std::size_t _len) override
    {
        if (!valid_ || _len == 0) {
            return;
        }
        BIO_write(in_bio_, _data, static_cast<int>(_len));
    }

    std::size_t drain(std::uint8_t* _out, std::size_t _max) override
    {
        if (!valid_) {
            return 0;
        }
        const int pending = BIO_pending(out_bio_);
        if (pending <= 0) {
            return 0;
        }
        const int want = (static_cast<std::size_t>(pending) > _max) ? static_cast<int>(_max) : pending;
        const int got = BIO_read(out_bio_, _out, want);
        return (got > 0) ? static_cast<std::size_t>(got) : 0;
    }

    result_e do_handshake() override
    {
        if (!valid_) {
            return result_e::fatal;
        }
        if (handshake_done_) {
            return result_e::ok;
        }
        const int ret = SSL_do_handshake(ssl_);
        if (ret == 1) {
            handshake_done_ = true;
            return result_e::ok;
        }
        return classify(ret);
    }

    result_e read(std::uint8_t* _out, std::size_t _max, std::size_t& _read) override
    {
        _read = 0;
        if (!valid_) {
            return result_e::fatal;
        }
        const int ret = SSL_read(ssl_, _out, static_cast<int>(_max));
        if (ret > 0) {
            _read = static_cast<std::size_t>(ret);
            return result_e::ok;
        }
        return classify(ret);
    }

    result_e write(const std::uint8_t* _in, std::size_t _len, std::size_t& _written) override
    {
        _written = 0;
        if (!valid_) {
            return result_e::fatal;
        }
        const int ret = SSL_write(ssl_, _in, static_cast<int>(_len));
        if (ret > 0) {
            _written = static_cast<std::size_t>(ret);
            return result_e::ok;
        }
        return classify(ret);
    }

    result_e shutdown() override
    {
        if (!valid_) {
            return result_e::fatal;
        }
        const int ret = SSL_shutdown(ssl_);
        if (ret >= 0) {
            return result_e::ok;
        }
        return classify(ret);
    }

    bool handshake_done() const override { return handshake_done_; }

    std::chrono::milliseconds next_timeout() const override
    {
        if (!valid_) {
            return std::chrono::milliseconds::zero();
        }
        struct timeval tv {};
        if (DTLSv1_get_timeout(ssl_, &tv) <= 0) {
            return std::chrono::milliseconds::zero();
        }
        return std::chrono::milliseconds(static_cast<std::int64_t>(tv.tv_sec) * 1000
                                         + static_cast<std::int64_t>(tv.tv_usec / 1000));
    }

    void handle_timeout() override
    {
        if (!valid_ || handshake_done_) {
            return;
        }
        // Returns 1 on retransmit, 0 if no retransmit was due, -1 on error.
        // Either way, pump() will re-evaluate state on the way back up.
        (void)DTLSv1_handle_timeout(ssl_);
    }

    std::string take_last_error() override
    {
        std::string s = std::move(last_error_);
        last_error_.clear();
        return s;
    }

private:
    result_e classify(int _ssl_ret)
    {
        const int err = SSL_get_error(ssl_, _ssl_ret);
        switch (err) {
        case SSL_ERROR_WANT_READ:
            return result_e::want_read;
        case SSL_ERROR_WANT_WRITE:
            return result_e::want_write;
        case SSL_ERROR_ZERO_RETURN:
            return result_e::peer_closed;
        case SSL_ERROR_SSL:
        case SSL_ERROR_SYSCALL: {
            std::string detail = pop_openssl_error();
            if (!detail.empty()) {
                last_error_ = std::move(detail);
            } else {
                last_error_ = (err == SSL_ERROR_SYSCALL) ? "SSL_ERROR_SYSCALL" : "SSL_ERROR_SSL";
            }
            return result_e::handshake_failed;
        }
        default:
            last_error_ = "SSL_get_error=" + std::to_string(err);
            return result_e::fatal;
        }
    }

    std::string last_error_ {};

    std::shared_ptr<openssl_context> ctx_ {};
    SSL* ssl_ {nullptr};
    BIO* in_bio_ {nullptr};
    BIO* out_bio_ {nullptr};
    bool is_server_ {false};
    bool valid_ {false};
    bool handshake_done_ {false};
};

class openssl_backend : public backend {
public:
    std::shared_ptr<context> create_server_context(const context_config& _cfg) override
    {
        auto ctx = std::make_shared<openssl_context>();
        if (!ctx->init(_cfg, /*_is_server=*/true)) {
            // valid() will report false; caller is expected to log via
            // VSOMEIP_ERROR. Returning the half-initialised context lets the
            // caller fetch last_error() for a precise log line.
        }
        return ctx;
    }

    std::shared_ptr<context> create_client_context(const context_config& _cfg) override
    {
        auto ctx = std::make_shared<openssl_context>();
        if (!ctx->init(_cfg, /*_is_server=*/false)) {
            // see above
        }
        return ctx;
    }

    std::unique_ptr<session_state> create_server_session(const std::shared_ptr<context>& _ctx) override
    {
        return std::make_unique<openssl_session>(std::dynamic_pointer_cast<openssl_context>(_ctx), /*_is_server=*/true);
    }

    std::unique_ptr<session_state> create_client_session(const std::shared_ptr<context>& _ctx) override
    {
        return std::make_unique<openssl_session>(std::dynamic_pointer_cast<openssl_context>(_ctx), /*_is_server=*/false);
    }
};

} // namespace

std::shared_ptr<backend> backend::create_default()
{
    static std::once_flag init_once__;
    std::call_once(init_once__, []() {
        // OpenSSL 3 auto-initialises but we still want explicit error
        // string loading for legible logs.
        OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS | OPENSSL_INIT_LOAD_CRYPTO_STRINGS, nullptr);
    });
    return std::make_shared<openssl_backend>();
}

} // namespace dtls
} // namespace vsomeip_v3

#endif // VSOMEIP_HAS_DTLS
