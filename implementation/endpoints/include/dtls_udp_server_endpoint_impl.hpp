// Copyright (C) 2014-2026 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#pragma once

#ifdef VSOMEIP_HAS_DTLS

#include <map>
#include <memory>
#include <mutex>

#include <boost/asio/ip/udp.hpp>

#include "server_endpoint_impl.hpp"
#include "udp_socket.hpp"
#include "dtls_backend.hpp"
#include "dtls_session.hpp"

namespace vsomeip_v3 {

// DTLS UDP server endpoint. Sibling of udp_server_endpoint_impl (ADR-001) —
// the existing UDP endpoint is left untouched. Each remote (IP, port) tuple
// owns its own dtls::session (ADR-003). Multicast SD remains plaintext on
// udp_server_endpoint_impl; this class never participates in multicast
// (ADR-005).
//
// Construction is identical to udp_server_endpoint_impl. The endpoint is
// instantiated by endpoint_manager_impl::find_or_create_server_endpoint when
// the service has an `unreliable_secure` port configured.
class dtls_udp_server_endpoint_impl : public server_endpoint_impl<boost::asio::ip::udp> {
public:
    using base = server_endpoint_impl<boost::asio::ip::udp>;
    using endpoint_type = base::endpoint_type;

    dtls_udp_server_endpoint_impl() = delete;
    dtls_udp_server_endpoint_impl(const dtls_udp_server_endpoint_impl&) = delete;
    dtls_udp_server_endpoint_impl(dtls_udp_server_endpoint_impl&&) = delete;
    dtls_udp_server_endpoint_impl(const std::shared_ptr<boardnet_endpoint_host>& _boardnet_endpoint_host,
                                  const std::shared_ptr<boardnet_routing_host>& _routing_host,
                                  boost::asio::io_context& _io,
                                  const std::shared_ptr<configuration>& _configuration,
                                  const std::shared_ptr<dtls::backend>& _backend,
                                  const std::shared_ptr<dtls::context>& _ctx);
    ~dtls_udp_server_endpoint_impl() override;

    dtls_udp_server_endpoint_impl& operator=(const dtls_udp_server_endpoint_impl&) = delete;
    dtls_udp_server_endpoint_impl& operator=(dtls_udp_server_endpoint_impl&&) = delete;

    // server_endpoint_impl interface
    void init(const endpoint_type& _local, boost::system::error_code& _error) override;
    void start() override;
    void stop(bool _due_to_error) override;
    void restart(bool _force) override;
    void receive() override;

    bool send_to(const std::shared_ptr<endpoint_definition> _target, const byte_t* _data, uint32_t _size) override;
    bool send_error(const std::shared_ptr<endpoint_definition> _target, const byte_t* _data, uint32_t _size) override;
    bool send_queued(const target_data_iterator_type _it) override;
    void get_configured_times_from_endpoint(service_t _service, method_t _method,
                                            std::chrono::nanoseconds* _debouncing,
                                            std::chrono::nanoseconds* _maximum_retention) const override;

    void add_default_target(service_t _service, const std::string& _address, uint16_t _port) override;
    void remove_default_target(service_t _service) override;
    bool get_default_target(service_t _service, endpoint_type& _target) const override;

    uint16_t get_local_port() const override;
    bool is_local() const override;
    void print_status() override;
    bool is_reliable() const override;

private:
    void on_unicast_received(const boost::system::error_code& _error, std::size_t _bytes,
                             const message_buffer_t& _recv_buffer);
    void dispatch_to_session(const endpoint_type& _peer, const byte_t* _data, std::size_t _len);
    void on_session_state(const endpoint_type& _peer, bool _ok, const std::string& _reason);
    void on_plaintext(const std::uint8_t* _data, std::size_t _len, const endpoint_type& _peer);
    bool send_ciphertext(const std::uint8_t* _data, std::size_t _len, const endpoint_type& _peer);
    std::string get_remote_information(const target_data_iterator_type _it) const override;
    std::string get_remote_information(const endpoint_type& _remote) const override;
    bool tp_segmentation_enabled(service_t _service, instance_t _instance, method_t _method) const override;

    mutable std::mutex sync_;
    std::unique_ptr<udp_socket> socket_;
    endpoint_type remote_;
    std::shared_ptr<dtls::backend> backend_;
    std::shared_ptr<dtls::context> ctx_;
    std::map<endpoint_type, std::shared_ptr<dtls::session>> sessions_;
    std::map<service_t, endpoint_type> default_targets_;
    std::atomic<bool> is_stopped_ {true};
};

} // namespace vsomeip_v3

#endif // VSOMEIP_HAS_DTLS
