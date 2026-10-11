// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0

// Compiled separately with the platform libc++ namespace (__1), not the NDK
// namespace (__ndk1). The required interface symbols are resolved by the caller.
// No platform C++ object or allocation crosses this translation unit's C API.
#include <cstdint>
#include <vector>
#include <cerrno>
#include "../../third_party/aosp-netd-api28/DnsTlsServer.h"
#include "../../third_party/aosp-netd-api28/ResolverController.h"

extern "C" int ae_platform_private_dns28(void *address, uint32_t network) {
    if (!address)
        return -ENOTSUP;
    using Controller = android::net::ResolverController;
    using Read = Controller::PrivateDnsStatus (*)(const Controller *, unsigned);
    // This API28 controller has no instance state: its accessor reads the
    // synchronized process-wide configuration. Use an actual matching object.
    // All platform containers are destroyed inside this __1 translation unit.
    Controller controller;
    const auto status = reinterpret_cast<Read>(address)(&controller, network);
    return status.mode == android::net::PrivateDnsMode::OFF ? 0 : -ENOTSUP;
}

extern "C" int ae_platform_list_caches(void *address, uint32_t *output, uint32_t capacity) {
    if (!address || !output || !capacity)
        return -1;
    using List = std::vector<unsigned> (*)();
    const auto values = reinterpret_cast<List>(address)();
    uint32_t count = 0;
    for (const unsigned id : values) {
        if (!id || id > 0xffffU)
            continue;
        if (count == capacity)
            return -1;
        uint32_t position = count;
        while (position && output[position - 1] > id) {
            output[position] = output[position - 1];
            --position;
        }
        if (position && output[position - 1] == id)
            return -1;
        output[position] = id;
        ++count;
    }
    return static_cast<int>(count);
}
