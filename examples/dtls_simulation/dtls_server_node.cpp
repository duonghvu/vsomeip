// Copyright (C) 2014-2026 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// dtls_server_node — standalone simulator for the DTLS server endpoint.
// One UDP socket, one dtls::session per peer (IP, port) tuple, mutual auth.
// Echoes every plaintext payload it receives so the client can confirm
// data transfer back and forth.

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <map>
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
    for (std::size_t i = 0; i < _len && i < 32; ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(_data[i]) << ' ';
    }
    if (_len > 32) {
        std::cout << "...";
    }
    std::cout << std::dec << '\n';
}

class server_node {
public:
    server_node(asio::io_context& _io, const std::string& _bind_addr, std::uint16_t _bind_port,
                const context_config& _cfg)
        : io_(_io)
        , socket_(_io, udp::endpoint(asio::ip::make_address(_bind_addr), _bind_port))
        , backend_(backend::create_default())
        , ctx_(backend_->create_server_context(_cfg))
        , recv_buf_(65535, 0)
    {
        if (!ctx_ || !ctx_->valid()) {
            std::cerr << "[server] context init failed: "
                      << (ctx_ ? ctx_->last_error() : std::string("null context")) << '\n';
            std::exit(1);
        }
        std::cout << "[server] listening on " << _bind_addr << ':' << _bind_port << '\n';
    }

    void start() { receive(); }

private:
    void receive()
    {
        socket_.async_receive_from(asio::buffer(recv_buf_), remote_,
                                   [this](const boost::system::error_code& _ec, std::size_t _bytes) {
                                       if (_ec) {
                                           std::cerr << "[server] recv error: " << _ec.message() << '\n';
                                           return;
                                       }
                                       on_datagram(_bytes);
                                       receive();
                                   });
    }

    void on_datagram(std::size_t _bytes)
    {
        std::cout << "[server] <- " << remote_ << ' ' << _bytes << " bytes ciphertext\n";
        auto it = sessions_.find(remote_);
        if (it == sessions_.end()) {
            std::cout << "[server] new peer " << remote_ << '\n';
            auto sess = std::make_shared<session>(
                io_, ctx_, backend_, remote_, /*_is_server=*/true,
                [this](const std::uint8_t* _d, std::size_t _l, const udp::endpoint& _peer) {
                    boost::system::error_code ec;
                    const auto n = socket_.send_to(asio::buffer(_d, _l), _peer, 0, ec);
                    std::cout << "[server] -> " << _peer << ' ' << n << " bytes ciphertext "
                              << (ec ? ec.message() : "ok") << '\n';
                    return !ec;
                },
                [this](const std::uint8_t* _d, std::size_t _l, const udp::endpoint& _peer) {
                    log_hex("[server] plaintext rx", _d, _l);
                    auto it2 = sessions_.find(_peer);
                    if (it2 != sessions_.end()) {
                        // Echo back with a "pong:" prefix to make round-trip
                        // unambiguous in the client log.
                        std::vector<std::uint8_t> reply;
                        reply.reserve(_l + 5);
                        const char* prefix = "pong:";
                        reply.insert(reply.end(), prefix, prefix + 5);
                        reply.insert(reply.end(), _d, _d + _l);
                        const bool ok = it2->second->send_plaintext(reply.data(), reply.size());
                        std::cout << "[server] echo " << (ok ? "ok" : "DROPPED") << '\n';
                    }
                },
                [](const udp::endpoint& _peer, bool _ok, const std::string& _why) {
                    std::cout << "[server] handshake " << (_ok ? "OK" : "FAIL")
                              << " with " << _peer << (_why.empty() ? "" : " (" + _why + ")") << '\n';
                });
            it = sessions_.emplace(remote_, sess).first;
            sess->start();
        }
        it->second->feed_datagram(recv_buf_.data(), _bytes);
    }

    asio::io_context& io_;
    udp::socket socket_;
    udp::endpoint remote_;
    std::shared_ptr<backend> backend_;
    std::shared_ptr<context> ctx_;
    std::vector<std::uint8_t> recv_buf_;
    std::map<udp::endpoint, std::shared_ptr<session>> sessions_;
};

void usage(const char* _argv0)
{
    std::cerr << "usage: " << _argv0
              << " --cert <pem> --key <pem> --ca <pem>"
              << " [--bind 127.0.0.1] [--port 32444] [--no-verify]\n";
}

} // namespace

int main(int _argc, char** _argv)
{
    std::cout << std::unitbuf;
    std::cerr << std::unitbuf;
    context_config cfg;
    std::string bind_addr = "127.0.0.1";
    std::uint16_t bind_port = 32444;

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
        } else if (a == "--bind") {
            bind_addr = next("--bind");
        } else if (a == "--port") {
            bind_port = static_cast<std::uint16_t>(std::stoi(next("--port")));
        } else if (a == "--no-verify") {
            cfg.verify_peer_ = false;
        } else if (a == "--cipher") {
            cfg.cipher_list_ = next("--cipher");
        } else {
            usage(_argv[0]);
            return 2;
        }
    }

    if (cfg.certificate_.empty() || cfg.private_key_.empty()) {
        usage(_argv[0]);
        return 2;
    }

    asio::io_context io;
    server_node node(io, bind_addr, bind_port, cfg);
    node.start();
    io.run();
    return 0;
}
