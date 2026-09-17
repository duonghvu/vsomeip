// Copyright (C) 2014-2026 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#pragma once

#ifdef VSOMEIP_HAS_DTLS

#include <memory>

#include <boost/asio/ip/udp.hpp>

#include "client_endpoint_impl.hpp"
#include "dtls_backend.hpp"
#include "dtls_session.hpp"

namespace vsomeip_v3 {

// DTLS UDP client endpoint. Sibling of udp_client_endpoint_impl (ADR-001).
// Owns one dtls::session per remote service (ADR-003).
class dtls_udp_client_endpoint_impl : public client_endpoint_impl<boost::asio::ip::udp> {
public:
    using base = client_endpoint_impl<boost::asio::ip::udp>;
    using endpoint_type = base::endpoint_type;

    dtls_udp_client_endpoint_impl(const std::shared_ptr<boardnet_endpoint_host>& _boardnet_endpoint_host,
                                  const std::shared_ptr<boardnet_routing_host>& _routing_host,
                                  const endpoint_type& _local, const endpoint_type& _remote,
                                  boost::asio::io_context& _io,
                                  const std::shared_ptr<configuration>& _configuration,
                                  const std::shared_ptr<dtls::backend>& _backend,
                                  const std::shared_ptr<dtls::context>& _ctx);
    ~dtls_udp_client_endpoint_impl() override;

    void start() override;
    void restart(bool _force) override;

    std::uint16_t get_local_port() const override;
    bool get_remote_address(boost::asio::ip::address& _address) const override;
    std::uint16_t get_remote_port() const override;
    bool is_local() const override;
    void print_status() override;
    bool is_reliable() const override;

    void receive_cbk(boost::system::error_code const& _error, std::size_t _bytes,
                     const message_buffer_ptr_t& _recv_buffer);
    void send_cbk(boost::system::error_code const& _error, std::size_t _bytes,
                  const message_buffer_ptr_t& _sent_msg);

private:
    void send_queued(std::pair<message_buffer_ptr_t, uint32_t>& _entry) override;
    void connect() override;
    void receive() override;
    void get_configured_times_from_endpoint(service_t _service, method_t _method,
                                            std::chrono::nanoseconds* _debouncing,
                                            std::chrono::nanoseconds* _maximum_retention) const override;
    bool tp_segmentation_enabled(service_t _service, instance_t _instance, method_t _method) const override;
    std::string get_address_port_remote() const override;
    std::string get_address_port_local() const override;
    std::string get_remote_information() const override;

    void on_session_state(const endpoint_type& _peer, bool _ok, const std::string& _reason);
    void on_plaintext(const std::uint8_t* _data, std::size_t _len, const endpoint_type& _peer);
    bool send_ciphertext(const std::uint8_t* _data, std::size_t _len, const endpoint_type& _peer);

    const endpoint_type remote_;
    std::shared_ptr<dtls::backend> backend_;
    std::shared_ptr<dtls::context> ctx_;
    std::shared_ptr<dtls::session> session_;
};

} // namespace vsomeip_v3

#endif // VSOMEIP_HAS_DTLS
