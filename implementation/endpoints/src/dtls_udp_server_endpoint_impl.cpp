// Copyright (C) 2014-2026 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifdef VSOMEIP_HAS_DTLS

#include "../include/dtls_udp_server_endpoint_impl.hpp"

#include <vsomeip/internal/logger.hpp>

#include "../../routing/include/boardnet_routing_host.hpp"
#include "../include/asio_socket_factory.hpp"
#include "../include/endpoint_definition.hpp"

namespace vsomeip_v3 {

dtls_udp_server_endpoint_impl::dtls_udp_server_endpoint_impl(
    const std::shared_ptr<boardnet_endpoint_host>& _boardnet_endpoint_host,
    const std::shared_ptr<boardnet_routing_host>& _routing_host,
    boost::asio::io_context& _io,
    const std::shared_ptr<configuration>& _configuration,
    const std::shared_ptr<dtls::backend>& _backend,
    const std::shared_ptr<dtls::context>& _ctx)
    : base(_boardnet_endpoint_host, _routing_host, _io, _configuration)
    , backend_(_backend)
    , ctx_(_ctx)
{
}

dtls_udp_server_endpoint_impl::~dtls_udp_server_endpoint_impl() = default;

void dtls_udp_server_endpoint_impl::init(const endpoint_type& _local, boost::system::error_code& _error)
{
    std::scoped_lock lk(sync_);
    socket_ = asio_socket_factory::create_udp_socket(io_, _error);
    if (_error) {
        VSOMEIP_ERROR << "DTLS server: socket create failed: " << _error.message();
        return;
    }
    socket_->open(_local.protocol(), _error);
    if (_error) {
        return;
    }
    socket_->bind(_local, _error);
    if (_error) {
        VSOMEIP_ERROR << "DTLS server: bind to " << _local << " failed: " << _error.message();
    }
}

void dtls_udp_server_endpoint_impl::start()
{
    is_stopped_ = false;
    receive();
}

void dtls_udp_server_endpoint_impl::stop(bool /*_due_to_error*/)
{
    std::scoped_lock lk(sync_);
    is_stopped_ = true;
    for (auto& [peer, sess] : sessions_) {
        sess->shutdown();
    }
    sessions_.clear();
    boost::system::error_code ec;
    if (socket_) {
        socket_->close(ec);
    }
}

void dtls_udp_server_endpoint_impl::restart(bool _force)
{
    stop(/*_due_to_error=*/false);
    boost::system::error_code ec;
    init(local_, ec);
    if (!ec) {
        start();
    } else if (_force) {
        VSOMEIP_ERROR << "DTLS server: restart bind failed: " << ec.message();
    }
}

void dtls_udp_server_endpoint_impl::receive()
{
    if (is_stopped_) {
        return;
    }
    auto buf = std::make_shared<message_buffer_t>(VSOMEIP_MAX_UDP_MESSAGE_SIZE);
    auto self = std::dynamic_pointer_cast<dtls_udp_server_endpoint_impl>(shared_from_this());
    socket_->async_receive_from(
        boost::asio::buffer(*buf), remote_,
        [self, buf](const boost::system::error_code& _error, std::size_t _bytes) {
            self->on_unicast_received(_error, _bytes, *buf);
        });
}

void dtls_udp_server_endpoint_impl::on_unicast_received(const boost::system::error_code& _error,
                                                        std::size_t _bytes,
                                                        const message_buffer_t& _recv_buffer)
{
    if (!_error && _bytes > 0) {
        dispatch_to_session(remote_, _recv_buffer.data(), _bytes);
    }
    receive();
}

void dtls_udp_server_endpoint_impl::dispatch_to_session(const endpoint_type& _peer,
                                                        const byte_t* _data, std::size_t _len)
{
    std::shared_ptr<dtls::session> sess;
    {
        std::scoped_lock lk(sync_);
        auto it = sessions_.find(_peer);
        if (it == sessions_.end()) {
            sess = std::make_shared<dtls::session>(
                io_, ctx_, backend_, _peer, /*_is_server=*/true,
                [self = shared_from_this(), this](const std::uint8_t* _d, std::size_t _l, const endpoint_type& _p) {
                    return send_ciphertext(_d, _l, _p);
                },
                [self = shared_from_this(), this](const std::uint8_t* _d, std::size_t _l, const endpoint_type& _p) {
                    on_plaintext(_d, _l, _p);
                },
                [self = shared_from_this(), this](const endpoint_type& _p, bool _ok, const std::string& _why) {
                    on_session_state(_p, _ok, _why);
                });
            sessions_.emplace(_peer, sess);
            sess->start();
        } else {
            sess = it->second;
        }
    }
    sess->feed_datagram(_data, _len);
}

void dtls_udp_server_endpoint_impl::on_session_state(const endpoint_type& _peer, bool _ok,
                                                     const std::string& _reason)
{
    if (_ok) {
        VSOMEIP_INFO << "DTLS server: handshake OK with " << _peer;
    } else {
        VSOMEIP_ERROR << "DTLS server: handshake failed with " << _peer << ": " << _reason;
        std::scoped_lock lk(sync_);
        sessions_.erase(_peer);
    }
}

void dtls_udp_server_endpoint_impl::on_plaintext(const std::uint8_t* _data, std::size_t _len,
                                                 const endpoint_type& _peer)
{
    // Forward decrypted SOME/IP message up the existing UDP server delivery
    // path. The base class's on_message handler does access-control, TP
    // reassembly, and routing dispatch — DTLS is transparent above this
    // line.
    on_message_received(_data, static_cast<length_t>(_len), /*_is_multicast=*/false, _peer);
}

bool dtls_udp_server_endpoint_impl::send_ciphertext(const std::uint8_t* _data, std::size_t _len,
                                                    const endpoint_type& _peer)
{
    if (!socket_ || is_stopped_) {
        return false;
    }
    boost::system::error_code ec;
    socket_->send_to(boost::asio::buffer(_data, _len), _peer, 0, ec);
    if (ec) {
        VSOMEIP_WARNING << "DTLS server: send_to " << _peer << " failed: " << ec.message();
        return false;
    }
    return true;
}

bool dtls_udp_server_endpoint_impl::send_to(const std::shared_ptr<endpoint_definition> _target,
                                            const byte_t* _data, uint32_t _size)
{
    if (!_target) {
        return false;
    }
    endpoint_type peer(_target->get_address(), _target->get_port());
    std::shared_ptr<dtls::session> sess;
    {
        std::scoped_lock lk(sync_);
        auto it = sessions_.find(peer);
        if (it == sessions_.end()) {
            return false;
        }
        sess = it->second;
    }
    return sess->send_plaintext(_data, _size);
}

bool dtls_udp_server_endpoint_impl::send_error(const std::shared_ptr<endpoint_definition> _target,
                                               const byte_t* _data, uint32_t _size)
{
    return send_to(_target, _data, _size);
}

bool dtls_udp_server_endpoint_impl::send_queued(const target_data_iterator_type _it)
{
    const auto& peer = _it->first;
    const auto& payload = _it->second;
    std::shared_ptr<dtls::session> sess;
    {
        std::scoped_lock lk(sync_);
        auto sit = sessions_.find(peer);
        if (sit == sessions_.end()) {
            return false;
        }
        sess = sit->second;
    }
    return sess->send_plaintext(payload.data(), payload.size());
}

void dtls_udp_server_endpoint_impl::get_configured_times_from_endpoint(
    service_t _service, method_t _method, std::chrono::nanoseconds* _debouncing,
    std::chrono::nanoseconds* _maximum_retention) const
{
    configuration_->get_configured_timing_responses(_service, get_address(), get_local_port(),
                                                    _method, _debouncing, _maximum_retention);
}

void dtls_udp_server_endpoint_impl::add_default_target(service_t _service, const std::string& _address,
                                                       uint16_t _port)
{
    std::scoped_lock lk(sync_);
    default_targets_[_service] = endpoint_type(boost::asio::ip::make_address(_address), _port);
}

void dtls_udp_server_endpoint_impl::remove_default_target(service_t _service)
{
    std::scoped_lock lk(sync_);
    default_targets_.erase(_service);
}

bool dtls_udp_server_endpoint_impl::get_default_target(service_t _service, endpoint_type& _target) const
{
    std::scoped_lock lk(sync_);
    auto it = default_targets_.find(_service);
    if (it == default_targets_.end()) {
        return false;
    }
    _target = it->second;
    return true;
}

uint16_t dtls_udp_server_endpoint_impl::get_local_port() const
{
    if (!socket_) {
        return 0;
    }
    boost::system::error_code ec;
    auto local = socket_->local_endpoint(ec);
    return ec ? 0 : local.port();
}

bool dtls_udp_server_endpoint_impl::is_local() const { return false; }

void dtls_udp_server_endpoint_impl::print_status()
{
    std::scoped_lock lk(sync_);
    VSOMEIP_INFO << "DTLS server endpoint port=" << get_local_port()
                 << " sessions=" << sessions_.size();
}

bool dtls_udp_server_endpoint_impl::is_reliable() const { return false; }

std::string dtls_udp_server_endpoint_impl::get_remote_information(
    const target_data_iterator_type _it) const
{
    return get_remote_information(_it->first);
}

std::string dtls_udp_server_endpoint_impl::get_remote_information(const endpoint_type& _remote) const
{
    return _remote.address().to_string() + ":" + std::to_string(_remote.port()) + " (DTLS)";
}

bool dtls_udp_server_endpoint_impl::tp_segmentation_enabled(service_t _service, instance_t _instance,
                                                            method_t _method) const
{
    return configuration_->is_tp_server(_service, _instance, _method);
}

} // namespace vsomeip_v3

#endif // VSOMEIP_HAS_DTLS
