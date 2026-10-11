// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0

#pragma once
#include <cstdint>
bool ae_runtime_init(uint64_t instance, uint32_t api, uint32_t modes, uint32_t flags);
void ae_runtime_serve(int companion_channel);
void ae_runtime_reap();
void ae_runtime_network_changed();
void ae_runtime_lock();
void ae_runtime_unlock();
class AeRuntimeGuard {
  public:
    AeRuntimeGuard() {
        ae_runtime_lock();
    }
    ~AeRuntimeGuard() {
        ae_runtime_unlock();
    }
};
