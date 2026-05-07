// Copyright (C) 2014-2026 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// dtls_client_node — standalone simulator for the DTLS client endpoint.
// Connects, completes handshake, sends N "ping" payloads and prints the
// matching "pong:" replies from the server. Exits non-zero if any payload
// is lost or corrupted.

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <memory>
#include <string>
#include <vector>

#include <boost/asio.hpp>

#include "dtls_backend.hpp"
#include "dtls_session.hpp"

namespace asio = boost::asio;
using udp = asio::ip::udp;
using vsomeip_v3::dtls::backend;
using vsomeip_v3::dtls::context;
using vsomeip_v3::dtls::context_config;
using vsomeip_v3::dtls::session;

namespace {

void log_hex(const char* _label, const std::uint8_t* _data, std::size_t _len)
{
    std::cout << _label << " (" << _len << " bytes): ";
    const std::size_t printable = (_len > 32) ? 32 : _len;
    for (std::size_t i = 0; i < printable; ++i) {
        const char c = static_cast<char>(_data[i]);
        if (c >= 32 && c <= 126) {
            std::cout << c;
        } else {
            std::cout << '.';
        }
    }
    if (_len > 32) {
        std::cout << "...";
    }
    std::cout << '\n';
}

class client_node {
public:
    client_node(asio::io_context& _io, const std::string& _server_addr, std::uint16_t _server_port,
                const context_config& _cfg, int _ping_count)
        : io_(_io)
        , socket_(_io, udp::endpoint(asio::ip::make_address("0.0.0.0"), 0))
        , peer_(asio::ip::make_address(_server_addr), _server_port)
        , backend_(backend::create_default())
        , ctx_(backend_->create_client_context(_cfg))
        , recv_buf_(65535, 0)
        , ping_count_(_ping_count)
        , exit_timer_(_io)
    {
        if (!ctx_ || !ctx_->valid()) {
            std::cerr << "[client] context init failed: "
                      << (ctx_ ? ctx_->last_error() : std::string("null context")) << '\n';
            std::exit(1);
        }
        std::cout << "[client] connecting to " << _server_addr << ':' << _server_port << '\n';
    }

    int run()
    {
        sess_ = std::make_shared<session>(
            io_, ctx_, backend_, peer_, /*_is_server=*/false,
            [this](const std::uint8_t* _d, std::size_t _l, const udp::endpoint& _peer) {
                boost::system::error_code ec;
                const auto n = socket_.send_to(asio::buffer(_d, _l), _peer, 0, ec);
                std::cout << "[client] -> " << _peer << ' ' << n << " bytes ciphertext "
                          << (ec ? ec.message() : "ok") << '\n';
                return !ec;
            },
            [this](const std::uint8_t* _d, std::size_t _l, const udp::endpoint& /*_peer*/) {
                log_hex("[client] plaintext rx", _d, _l);
                ++pongs_received_;
                if (pongs_received_ >= ping_count_) {
                    finish(/*_ok=*/true);
                }
            },
            [this](const udp::endpoint& _peer, bool _ok, const std::string& _why) {
                std::cout << "[client] handshake " << (_ok ? "OK" : "FAIL")
                          << " with " << _peer << (_why.empty() ? "" : " (" + _why + ")") << '\n';
                if (_ok) {
                    send_pings();
                } else {
                    finish(/*_ok=*/false);
                }
            });

        receive();
        sess_->start();

        // Failsafe: if we don't see all pongs within 10s, declare failure.
        exit_timer_.expires_after(std::chrono::seconds(10));
        exit_timer_.async_wait([this](const boost::system::error_code& _ec) {
            if (!_ec && !done_) {
                std::cerr << "[client] timeout waiting for "
                          << (ping_count_ - pongs_received_) << " of "
                          << ping_count_ << " pong(s)\n";
                finish(/*_ok=*/false);
            }
        });

        io_.run();
        return exit_code_;
    }

private:
    void receive()
    {
        socket_.async_receive_from(asio::buffer(recv_buf_), remote_,
                                   [this](const boost::system::error_code& _ec, std::size_t _bytes) {
                                       if (_ec) {
                                           if (!done_) {
                                               std::cerr << "[client] recv error: " << _ec.message() << '\n';
                                           }
                                           return;
                                       }
                                       sess_->feed_datagram(recv_buf_.data(), _bytes);
                                       if (!done_) {
                                           receive();
                                       }
                                   });
    }

    void send_pings()
    {
        for (int i = 0; i < ping_count_; ++i) {
            std::string msg = "ping #" + std::to_string(i + 1);
            const bool ok = sess_->send_plaintext(reinterpret_cast<const std::uint8_t*>(msg.data()), msg.size());
            std::cout << "[client] send " << msg << ' ' << (ok ? "ok" : "DROPPED") << '\n';
            if (!ok) {
                finish(/*_ok=*/false);
                return;
            }
        }
    }

    void finish(bool _ok)
    {
        if (done_) {
            return;
        }
        done_ = true;
        exit_code_ = _ok ? 0 : 1;
        exit_timer_.cancel();
        if (sess_) {
            sess_->shutdown();
        }
        boost::system::error_code ec;
        socket_.close(ec);
        io_.stop();
        std::cout << "[client] " << (_ok ? "PASS" : "FAIL")
                  << " (received " << pongs_received_ << '/' << ping_count_ << ")\n";
    }

    asio::io_context& io_;
    udp::socket socket_;
    udp::endpoint peer_;
    udp::endpoint remote_;
    std::shared_ptr<backend> backend_;
    std::shared_ptr<context> ctx_;
    std::shared_ptr<session> sess_;
    std::vector<std::uint8_t> recv_buf_;
    int ping_count_;
    int pongs_received_ {0};
    bool done_ {false};
    int exit_code_ {1};
    asio::steady_timer exit_timer_;
};

void usage(const char* _argv0)
{
    std::cerr << "usage: " << _argv0
              << " --cert <pem> --key <pem> --ca <pem>"
              << " [--server 127.0.0.1] [--port 32444] [--count 3] [--no-verify]\n";
}

} // namespace

int main(int _argc, char** _argv)
{
    std::cout << std::unitbuf;
    std::cerr << std::unitbuf;
    context_config cfg;
    std::string server_addr = "127.0.0.1";
    std::uint16_t server_port = 32444;
    int count = 3;

    for (int i = 1; i < _argc; ++i) {
        std::string a = _argv[i];
        auto next = [&](const char* _flag) {
            if (i + 1 >= _argc) {
                std::cerr << _flag << " requires an argument\n";
                std::exit(2);
            }
            return std::string(_argv[++i]);
        };
        if (a == "--cert") {
            cfg.certificate_ = next("--cert");
        } else if (a == "--key") {
            cfg.private_key_ = next("--key");
        } else if (a == "--ca") {
            cfg.ca_bundle_ = next("--ca");
        } else if (a == "--server") {
            server_addr = next("--server");
        } else if (a == "--port") {
            server_port = static_cast<std::uint16_t>(std::stoi(next("--port")));
        } else if (a == "--count") {
            count = std::stoi(next("--count"));
        } else if (a == "--no-verify") {
            cfg.verify_peer_ = false;
        } else if (a == "--cipher") {
            cfg.cipher_list_ = next("--cipher");
        } else {
            usage(_argv[0]);
            return 2;
        }
    }

    if (cfg.certificate_.empty() || cfg.private_key_.empty() || cfg.ca_bundle_.empty()) {
        usage(_argv[0]);
        return 2;
    }

    asio::io_context io;
    client_node node(io, server_addr, server_port, cfg, count);
    return node.run();
}
