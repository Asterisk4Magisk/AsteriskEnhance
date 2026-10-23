// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0

#pragma once
#include "../common/actor.h"
#include "resolver_bridge.h"
#include "zygisk_next_api.h"

// Initialize after the required netd/resolver interfaces have been resolved.
bool ae_backend_init(const ZygiskNextAPI *,
                     int sdk,
                     void *modern_bridge,
                     const char *resolver_path);
bool ae_backend_ready();
// Uses the verified original controller function, never the decorating hook.
// Returns 0, -EAGAIN when netd no longer resolves the network to itself
// (destroyed before its resolver cache), or -ENOTSUP.
int ae_original_dns_mark(uint32_t network, uint32_t *mark);
AeActorBackend ae_backend_callbacks();
int ae_backend_read(uint32_t network, AeDnsConfig *);
// API27 only, from resolver threads: true when selected queries on this
// original network must not use its isolated cache. No logging or failure state.
bool ae_backend_tls27_blocked(uint32_t network);
int ae_backend_networks(uint32_t *output, uint32_t capacity);
