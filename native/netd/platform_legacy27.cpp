// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0

// API27 interface adapter, compiled with the platform libc++ namespace.
#include <cstdint>
#include <cerrno>
#include <set>
#include <string>
#include <vector>
// Keep the historical declaration separate from the API28 controller's type.
#define android ae_platform27
#include "../../third_party/aosp-netd-api27/ResolverController.h"
#undef android

extern "C" int ae_platform_private_dns27(void *address,
                                         uint32_t network,
                                         const sockaddr_storage *servers,
                                         uint32_t count) {
    if (!address || !servers || !count)
        return -ENOTSUP;
    using Controller = ae_platform27::net::ResolverController;
    using Read = bool (*)(Controller *,
                          unsigned,
                          const sockaddr_storage &,
                          sockaddr_storage *,
                          std::set<std::vector<uint8_t>> *);
    // The accessor locks the process-global TLS provider table.
    Controller controller;
    for (uint32_t i = 0; i < count; ++i) {
        sockaddr_storage secure{};
        std::set<std::vector<uint8_t>> fingerprints;
        if (reinterpret_cast<Read>(address)(
                &controller, network, servers[i], &secure, &fingerprints))
            return -ENOTSUP;
    }
    return 0;
}
