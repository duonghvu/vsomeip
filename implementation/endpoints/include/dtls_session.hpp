// Copyright (C) 2014-2026 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#pragma once

#ifdef VSOMEIP_HAS_DTLS

#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <vector>

#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/steady_timer.hpp>

#include "dtls_backend.hpp"

namespace vsomeip_v3 {
namespace dtls {

// One DTLS session per peer (IP, port) tuple (ADR-003). A session owns the
// backend session_state and the asio steady_timer used for handshake
// retransmits. The session does NOT own the UDP socket — the dtls UDP
// endpoint (server or client) owns the socket and routes datagrams to the
// matching session via feed_datagram().
class session : public std::enable_shared_from_this<session> {
public:
    using udp_endpoint = boost::asio::ip::udp::endpoint;

    // Callback the session uses to send ciphertext outwards. Returns false on
    // error; the session does not retry — it relies on DTLS retransmit.
    using send_ciphertext_cbk = std::function<bool(const std::uint8_t*, std::size_t, const udp_endpoint&)>;

    // Callback the session invokes once decrypted plaintext is available. The
    // endpoint forwards this up the same path as the existing UDP endpoint
    // (`on_message`).
    using on_plaintext_cbk = std::function<void(const std::uint8_t*, std::size_t, const udp_endpoint&)>;

    // Callback raised when the handshake ends (success or failure). Lets the
    // server endpoint surface errors via VSOMEIP_ERROR + cleanup, and the
    // client endpoint move past `connect()` once handshake_done == true.
    using on_state_change_cbk = std::function<void(const udp_endpoint&, bool /*_handshake_ok*/, const std::string& /*_reason*/)>;

    session(boost::asio::io_context& _io,
            const std::shared_ptr<context>& _ctx,
            const std::shared_ptr<backend>& _backend,
            const udp_endpoint& _peer,
            bool _is_server,
            const send_ciphertext_cbk& _send,
            const on_plaintext_cbk& _on_plaintext,
            const on_state_change_cbk& _on_state);

    ~session();

    // Drive the handshake forwards (called both on session creation and from
    // the retransmit timer).
    void start();

    // Accept ciphertext that arrived for this peer.
    void feed_datagram(const std::uint8_t* _data, std::size_t _len);

    // Encrypt and send a SOME/IP plaintext payload. Returns false if the
    // handshake has not yet completed.
    bool send_plaintext(const std::uint8_t* _data, std::size_t _len);

    // Send a graceful close_notify; idempotent.
    void shutdown();

    bool is_ready() const { return state_->handshake_done(); }
    const udp_endpoint& peer() const { return peer_; }

private:
    void pump();
    void flush_outbound();
    void schedule_timer();
    void on_timer(const boost::system::error_code& _ec);

    boost::asio::io_context& io_;
    std::shared_ptr<context> ctx_;
    std::shared_ptr<backend> backend_;
    udp_endpoint peer_;
    bool is_server_;
    std::unique_ptr<session_state> state_;
    boost::asio::steady_timer timer_;
    send_ciphertext_cbk send_cbk_;
    on_plaintext_cbk on_plaintext_cbk_;
    on_state_change_cbk on_state_cbk_;
    std::vector<std::uint8_t> tx_buf_;
    std::vector<std::uint8_t> rx_buf_;
    bool reported_state_ {false};
    bool stopped_ {false};
};

} // namespace dtls
} // namespace vsomeip_v3

#endif // VSOMEIP_HAS_DTLS
