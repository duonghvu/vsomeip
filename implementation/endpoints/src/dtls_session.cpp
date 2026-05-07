// Copyright (C) 2014-2026 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifdef VSOMEIP_HAS_DTLS

#include "../include/dtls_session.hpp"

#include <algorithm>

namespace vsomeip_v3 {
namespace dtls {

namespace {
// 65535 covers the largest DTLS record we will ever buffer; SOME/IP-TP
// fragments below the path MTU well before reaching this size.
constexpr std::size_t kSessionBuf = 65535;
} // namespace

session::session(boost::asio::io_context& _io,
                 const std::shared_ptr<context>& _ctx,
                 const std::shared_ptr<backend>& _backend,
                 const udp_endpoint& _peer,
                 bool _is_server,
                 const send_ciphertext_cbk& _send,
                 const on_plaintext_cbk& _on_plaintext,
                 const on_state_change_cbk& _on_state)
    : io_(_io)
    , ctx_(_ctx)
    , backend_(_backend)
    , peer_(_peer)
    , is_server_(_is_server)
    , timer_(_io)
    , send_cbk_(_send)
    , on_plaintext_cbk_(_on_plaintext)
    , on_state_cbk_(_on_state)
    , tx_buf_(kSessionBuf, 0)
    , rx_buf_(kSessionBuf, 0)
{
    if (is_server_) {
        state_ = backend_->create_server_session(ctx_);
    } else {
        state_ = backend_->create_client_session(ctx_);
    }
}

session::~session()
{
    timer_.cancel();
}

void session::start()
{
    pump();
}

void session::feed_datagram(const std::uint8_t* _data, std::size_t _len)
{
    if (stopped_ || state_ == nullptr || _len == 0) {
        return;
    }
    state_->feed(_data, _len);
    pump();
}

bool session::send_plaintext(const std::uint8_t* _data, std::size_t _len)
{
    if (stopped_ || state_ == nullptr || !state_->handshake_done()) {
        return false;
    }
    std::size_t written = 0;
    const result_e r = state_->write(_data, _len, written);
    flush_outbound();
    return r == result_e::ok && written == _len;
}

void session::shutdown()
{
    if (stopped_ || state_ == nullptr) {
        return;
    }
    stopped_ = true;
    state_->shutdown();
    flush_outbound();
    timer_.cancel();
}

void session::pump()
{
    if (stopped_ || state_ == nullptr) {
        return;
    }

    if (!state_->handshake_done()) {
        const result_e hs = state_->do_handshake();
        flush_outbound();
        if (hs == result_e::ok) {
            if (!reported_state_ && on_state_cbk_) {
                reported_state_ = true;
                on_state_cbk_(peer_, true, std::string {});
            }
        } else if (hs == result_e::handshake_failed || hs == result_e::fatal || hs == result_e::peer_closed) {
            if (!reported_state_ && on_state_cbk_) {
                reported_state_ = true;
                std::string detail = state_->take_last_error();
                if (detail.empty()) {
                    detail = "DTLS handshake failed";
                }
                on_state_cbk_(peer_, false, detail);
            }
            stopped_ = true;
            return;
        } else {
            // want_read / want_write / handshake_in_progress: arm the timer
            // for a retransmit if OpenSSL asks for one.
            schedule_timer();
            // Even mid-handshake there may be application data buffered the
            // backend wants to flush; the flush_outbound() above handles it.
            return;
        }
    }

    // Drain any application records the backend has decoded.
    for (;;) {
        std::size_t got = 0;
        const result_e r = state_->read(rx_buf_.data(), rx_buf_.size(), got);
        if (r == result_e::ok && got > 0) {
            if (on_plaintext_cbk_) {
                on_plaintext_cbk_(rx_buf_.data(), got, peer_);
            }
            continue;
        }
        if (r == result_e::peer_closed) {
            stopped_ = true;
            if (on_state_cbk_) {
                on_state_cbk_(peer_, false, "peer close_notify");
            }
            break;
        }
        // want_read / want_write / fatal: nothing more to drain right now.
        break;
    }
    flush_outbound();
    schedule_timer();
}

void session::flush_outbound()
{
    if (state_ == nullptr || !send_cbk_) {
        return;
    }
    for (;;) {
        const std::size_t n = state_->drain(tx_buf_.data(), tx_buf_.size());
        if (n == 0) {
            break;
        }
        send_cbk_(tx_buf_.data(), n, peer_);
    }
}

void session::schedule_timer()
{
    if (stopped_ || state_ == nullptr) {
        return;
    }
    if (state_->handshake_done()) {
        return;
    }
    auto next = state_->next_timeout();
    if (next.count() <= 0) {
        return;
    }
    timer_.cancel();
    timer_.expires_after(next);
    auto self = shared_from_this();
    timer_.async_wait([self](const boost::system::error_code& _ec) { self->on_timer(_ec); });
}

void session::on_timer(const boost::system::error_code& _ec)
{
    if (_ec || stopped_ || state_ == nullptr) {
        return;
    }
    state_->handle_timeout();
    pump();
}

} // namespace dtls
} // namespace vsomeip_v3

#endif // VSOMEIP_HAS_DTLS
