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
bool ae_original_dns_mark(uint32_t network, uint32_t *mark);
AeActorBackend ae_backend_callbacks();
int ae_backend_read(uint32_t network, AeDnsConfig *);
int ae_backend_networks(uint32_t *output, uint32_t capacity);
