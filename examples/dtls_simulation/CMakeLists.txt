# Copyright (C) 2014-2026 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

# Standalone DTLS round-trip simulation. Two executables — dtls_server_node
# and dtls_client_node — link the new DTLS source files directly so the
# example is buildable on developer machines (incl. macOS) without porting
# the full libvsomeip3 to those targets. They exercise the same dtls_session
# and dtls_backend_openssl code that the DTLS UDP endpoints inside libvsomeip3
# use on Linux/QNX.

cmake_minimum_required(VERSION 3.16)
project(dtls_simulation CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if (POLICY CMP0167)
    cmake_policy(SET CMP0167 NEW)
endif ()

find_package(OpenSSL 3.0 REQUIRED)
# Modern Boost.Asio (>= 1.74) is header-only for the small subset we use
# (io_context, ip::udp, steady_timer). Linking the headers target is enough.
find_package(Boost 1.74 CONFIG REQUIRED)
find_package(Threads REQUIRED)

set(VSOMEIP_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../..")

set(DTLS_SOURCES
    "${VSOMEIP_ROOT}/implementation/endpoints/src/dtls_backend_openssl.cpp"
    "${VSOMEIP_ROOT}/implementation/endpoints/src/dtls_session.cpp"
)

add_library(dtls_simulation_core STATIC ${DTLS_SOURCES})
target_compile_definitions(dtls_simulation_core PUBLIC VSOMEIP_HAS_DTLS)
target_include_directories(dtls_simulation_core PUBLIC
    "${VSOMEIP_ROOT}/implementation/endpoints/include"
)
target_link_libraries(dtls_simulation_core PUBLIC
    OpenSSL::SSL
    OpenSSL::Crypto
    Boost::headers
    Threads::Threads
)
# Switch Boost.Asio to its header-only error code path so we don't need to
# link libboost_system (Boost 1.90 brew bottle ships only filesystem).
target_compile_definitions(dtls_simulation_core PUBLIC
    BOOST_ASIO_NO_DEPRECATED
    BOOST_ASIO_HAS_STD_INVOKE_RESULT
    BOOST_SYSTEM_NO_DEPRECATED
)

add_executable(dtls_server_node dtls_server_node.cpp)
target_link_libraries(dtls_server_node PRIVATE dtls_simulation_core)

add_executable(dtls_client_node dtls_client_node.cpp)
target_link_libraries(dtls_client_node PRIVATE dtls_simulation_core)
