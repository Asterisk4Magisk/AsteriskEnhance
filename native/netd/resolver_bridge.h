// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0

#pragma once
#include <stdint.h>

// Only POD data crosses the independently loaded Binder bridge boundary.
struct AeDnsConfig {
    uint32_t server_count;
    uint32_t domain_count;
    char servers[8][128];
    char domains[6][256];
    int32_t parameters[6];
};

#ifdef __cplusplus
extern "C" {
#endif
int ae_resolver_read_config(uint32_t network_id, struct AeDnsConfig *output);
int ae_resolver_reserve(uint32_t cache_id);
int ae_resolver_configure(uint32_t cache_id, const struct AeDnsConfig *config);
int ae_resolver_destroy(uint32_t cache_id);
#ifdef __cplusplus
}
#endif
