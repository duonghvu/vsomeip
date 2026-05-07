// Copyright (C) 2014-2026 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifdef VSOMEIP_HAS_DTLS

#include "../include/dtls_udp_client_endpoint_impl.hpp"

#include <vsomeip/internal/logger.hpp>

namespace vsomeip_v3 {

dtls_udp_client_endpoint_impl::dtls_udp_client_endpoint_impl(
    const std::shared_ptr<boardnet_endpoint_host>& _boardnet_endpoint_host,
    const std::shared_ptr<boardnet_routing_host>& _routing_host,
    const endpoint_type& _local, const endpoint_type& _remote,
    boost::asio::io_context& _io,
    const std::shared_ptr<configuration>& _configuration,
    const std::shared_ptr<dtls::backend>& _backend,
    const std::shared_ptr<dtls::context>& _ctx)
    : base(_boardnet_endpoint_host, _routing_host, _local, _io, _configuration)
    , remote_(_remote)
    , backend_(_backend)
    , ctx_(_ctx)
{
}

dtls_udp_client_endpoint_impl::~dtls_udp_client_endpoint_impl() = default;

void dtls_udp_client_endpoint_impl::start()
{
    connect();
}

void dtls_udp_client_endpoint_impl::restart(bool _force)
{
    if (session_) {
        session_->shutdown();
        session_.reset();
    }
    if (_force) {
        connect();
    }
}

void dtls_udp_client_endpoint_impl::connect()
{
    boost::system::error_code ec;
    socket_->open(remote_.protocol(), ec);
    if (ec) {
        VSOMEIP_ERROR << "DTLS client: open failed: " << ec.message();
        return;
    }
    socket_->bind(local_, ec);
    if (ec) {
        VSOMEIP_ERROR << "DTLS client: bind failed: " << ec.message();
        return;
    }

    auto self = std::dynamic_pointer_cast<dtls_udp_client_endpoint_impl>(shared_from_this());
    session_ = std::make_shared<dtls::session>(
        io_, ctx_, backend_, remote_, /*_is_server=*/false,
        [self](const std::uint8_t* _d, std::size_t _l, const endpoint_type& _p) {
            return self->send_ciphertext(_d, _l, _p);
        },
        [self](const std::uint8_t* _d, std::size_t _l, const endpoint_type& _p) {
            self->on_plaintext(_d, _l, _p);
        },
        [self](const endpoint_type& _p, bool _ok, const std::string& _why) {
            self->on_session_state(_p, _ok, _why);
        });

    session_->start();
    receive();
}

void dtls_udp_client_endpoint_impl::receive()
{
    auto buf = std::make_shared<message_buffer_t>(VSOMEIP_MAX_UDP_MESSAGE_SIZE);
    auto self = std::dynamic_pointer_cast<dtls_udp_client_endpoint_impl>(shared_from_this());
    socket_->async_receive_from(
        boost::asio::buffer(*buf), const_cast<endpoint_type&>(remote_),
        [self, buf](const boost::system::error_code& _error, std::size_t _bytes) {
            self->receive_cbk(_error, _bytes, buf);
        });
}

void dtls_udp_client_endpoint_impl::receive_cbk(boost::system::error_code const& _error,
                                                std::size_t _bytes,
                                                const message_buffer_ptr_t& _recv_buffer)
{
    if (!_error && _bytes > 0 && session_) {
        session_->feed_datagram(_recv_buffer->data(), _bytes);
    }
    if (!_error) {
        receive();
    }
}

void dtls_udp_client_endpoint_impl::send_queued(std::pair<message_buffer_ptr_t, uint32_t>& _entry)
{
    if (!session_ || !session_->is_ready()) {
        return; // base class will retry once handshake completes
    }
    session_->send_plaintext(_entry.first->data(), _entry.first->size());
}

void dtls_udp_client_endpoint_impl::on_session_state(const endpoint_type& _peer, bool _ok,
                                                     const std::string& _reason)
{
    if (_ok) {
        VSOMEIP_INFO << "DTLS client: handshake OK with " << _peer;
        // Trigger drain of the base-class send queue now that we are ready.
        flush_queue();
    } else {
        VSOMEIP_ERROR << "DTLS client: handshake failed with " << _peer << ": " << _reason;
    }
}

void dtls_udp_client_endpoint_impl::on_plaintext(const std::uint8_t* _data, std::size_t _len,
                                                 const endpoint_type& /*_peer*/)
{
    on_message_received(_data, static_cast<length_t>(_len));
}

bool dtls_udp_client_endpoint_impl::send_ciphertext(const std::uint8_t* _data, std::size_t _len,
                                                    const endpoint_type& _peer)
{
    boost::system::error_code ec;
    socket_->send_to(boost::asio::buffer(_data, _len), _peer, 0, ec);
    if (ec) {
        VSOMEIP_WARNING << "DTLS client: send_to " << _peer << " failed: " << ec.message();
        return false;
    }
    return true;
}

void dtls_udp_client_endpoint_impl::send_cbk(boost::system::error_code const& /*_error*/,
                                             std::size_t /*_bytes*/,
                                             const message_buffer_ptr_t& /*_sent_msg*/)
{
    // Direct sends complete synchronously above; this exists only for
    // base-class symmetry.
}

std::uint16_t dtls_udp_client_endpoint_impl::get_local_port() const
{
    boost::system::error_code ec;
    auto local = socket_ ? socket_->local_endpoint(ec) : endpoint_type {};
    return ec ? 0 : local.port();
}

bool dtls_udp_client_endpoint_impl::get_remote_address(boost::asio::ip::address& _address) const
{
    _address = remote_.address();
    return true;
}

std::uint16_t dtls_udp_client_endpoint_impl::get_remote_port() const { return remote_.port(); }
bool dtls_udp_client_endpoint_impl::is_local() const { return false; }
bool dtls_udp_client_endpoint_impl::is_reliable() const { return false; }

void dtls_udp_client_endpoint_impl::print_status()
{
    VSOMEIP_INFO << "DTLS client endpoint -> " << remote_
                 << (session_ && session_->is_ready() ? " ready" : " handshaking");
}

void dtls_udp_client_endpoint_impl::get_configured_times_from_endpoint(
    service_t _service, method_t _method, std::chrono::nanoseconds* _debouncing,
    std::chrono::nanoseconds* _maximum_retention) const
{
    configuration_->get_configured_timing_requests(_service, remote_.address().to_string(),
                                                    remote_.port(), _method,
                                                    _debouncing, _maximum_retention);
}

bool dtls_udp_client_endpoint_impl::tp_segmentation_enabled(service_t _service, instance_t _instance,
                                                            method_t _method) const
{
    return configuration_->is_tp_client(_service, remote_.address().to_string(), remote_.port(),
                                         _instance, _method);
}

std::string dtls_udp_client_endpoint_impl::get_address_port_remote() const
{
    return remote_.address().to_string() + ":" + std::to_string(remote_.port());
}

std::string dtls_udp_client_endpoint_impl::get_address_port_local() const
{
    return local_.address().to_string() + ":" + std::to_string(local_.port());
}

std::string dtls_udp_client_endpoint_impl::get_remote_information() const
{
    return get_address_port_remote() + " (DTLS)";
}

} // namespace vsomeip_v3

#endif // VSOMEIP_HAS_DTLS
