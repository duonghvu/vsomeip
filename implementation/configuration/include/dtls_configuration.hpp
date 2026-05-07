// Copyright (C) 2014-2026 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#pragma once

#ifdef VSOMEIP_HAS_DTLS

#include <chrono>
#include <map>
#include <string>

#include <boost/property_tree/ptree.hpp>

#include "../../endpoints/include/dtls_backend.hpp"

namespace vsomeip_v3 {

// Parsed contents of the global `dtls` JSON block. configuration_impl
// instantiates one of these and exposes it via a getter; both endpoint_impls
// (server / client) read it before constructing their dtls::context.
struct dtls_configuration {
    bool enabled_ {false};
    dtls::context_config context_ {};

    // Per-service unreliable_secure port: service_id → instance_id → port.
    // Populated alongside the existing reliable / unreliable port maps in
    // configuration_impl::load_service.
    std::map<std::uint16_t, std::map<std::uint16_t, std::uint16_t>> secure_ports_ {};

    // Helper: fill from the JSON ptree at the `dtls` node. Returns false
    // (and leaves *this in a defined-but-disabled state) if the node is
    // absent or malformed; configuration_impl::load_dtls() logs the reason
    // via VSOMEIP_WARNING in that case.
    bool load(const boost::property_tree::ptree& _node);
};

} // namespace vsomeip_v3

#endif // VSOMEIP_HAS_DTLS
