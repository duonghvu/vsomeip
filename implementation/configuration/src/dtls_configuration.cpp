// Copyright (C) 2014-2026 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifdef VSOMEIP_HAS_DTLS

#include "../include/dtls_configuration.hpp"

#include <algorithm>
#include <cctype>
#include <string>

namespace vsomeip_v3 {

namespace {

bool to_bool(const std::string& _s, bool _fallback)
{
    std::string s = _s;
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    if (s == "true" || s == "1" || s == "yes" || s == "on") {
        return true;
    }
    if (s == "false" || s == "0" || s == "no" || s == "off") {
        return false;
    }
    return _fallback;
}

} // namespace

bool dtls_configuration::load(const boost::property_tree::ptree& _node)
{
    enabled_ = to_bool(_node.get<std::string>("enable", "false"), false);

    context_.version_ = _node.get<std::string>("version", "1.2");
    context_.cipher_list_ = _node.get<std::string>("cipher_list", "ECDHE-ECDSA-AES128-GCM-SHA256");
    context_.certificate_ = _node.get<std::string>("certificate", "");
    context_.private_key_ = _node.get<std::string>("private_key", "");
    context_.ca_bundle_ = _node.get<std::string>("ca_bundle", "");
    context_.verify_peer_ = to_bool(_node.get<std::string>("verify_peer", "true"), true);
    context_.cookie_exchange_ = to_bool(_node.get<std::string>("cookie_exchange", "true"), true);

    const auto handshake_ms = _node.get<std::int64_t>("handshake_timeout_ms", 5000);
    context_.handshake_timeout_ = std::chrono::milliseconds(handshake_ms);

    if (enabled_) {
        // Mutual auth without a configured CA bundle is meaningless; downgrade
        // to disabled and let configuration_impl log a VSOMEIP_WARNING.
        if (context_.verify_peer_ && context_.ca_bundle_.empty()) {
            enabled_ = false;
            return false;
        }
        if (context_.certificate_.empty() || context_.private_key_.empty()) {
            enabled_ = false;
            return false;
        }
    }
    return true;
}

} // namespace vsomeip_v3

#endif // VSOMEIP_HAS_DTLS
