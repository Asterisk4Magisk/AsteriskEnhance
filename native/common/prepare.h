// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0

#pragma once
#include "policy.h"
#include <stddef.h>

#define AE_CONSUMER_VERSION 2U
#define AE_MAX_UIDS 8192U
#define AE_MAX_NETWORKS 64U
#define AE_PREPARE_FIXED_SIZE 48U
enum AeRunMode { AE_TPROXY = 1, AE_TUN2SOCKS = 2, AE_BPF2SOCKS = 3 };
struct AePrepare {
    uint64_t netd_instance;
    uint32_t run_mode, policy_mode, consumer_version, entry_port;
    uint32_t mark_mask, proxy_mark, direct_mark, uid_count;
    const uint32_t *uids;
    uint32_t bypass_count;
    const uint32_t *bypass_uids;
    uint32_t network_count;
    const uint32_t *networks;
};
// A fixed-width, little-endian schema. Unknown/trailing fields are rejected.
// Decode storage is caller-owned and remains valid until its next decode.
#ifdef __cplusplus
extern "C" {
#endif
AE_EXPORT int ae_prepare_valid(const struct AePrepare *);
AE_EXPORT size_t ae_prepare_storage_size(void);
AE_EXPORT int ae_prepare_decode(const void *, size_t, void *storage, struct AePrepare *);
AE_EXPORT size_t ae_prepare_encode(const struct AePrepare *, void *, size_t);
#ifdef __cplusplus
}
#endif
