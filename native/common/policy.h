// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0

#pragma once
#include <stdint.h>

#if defined(_WIN32)
#define AE_EXPORT __declspec(dllexport)
#else
#define AE_EXPORT __attribute__((visibility("default")))
#endif

struct AeContext {
    uint32_t app_netid, app_mark, dns_netid, dns_mark, uid;
};
struct AeCacheBinding {
    uint32_t network_id, cache_id;
};
enum AePolicyMode { AE_WHITELIST = 1, AE_BLACKLIST = 2, AE_GLOBAL = 3 };
enum AeDecision {
    AE_ORIGINAL = 0,
    AE_PROXY = 1,
    AE_DIRECT = 2,
    AE_CACHE_MISSING = 3,
    AE_MARK_CONFLICT = 4
};
struct AePolicy {
    uint64_t instance_id, generation, deadline_ms;
    uint32_t active, mode, mark_mask, proxy_mark, direct_mark;
    uint32_t uid_count;
    const uint32_t *uids;
    uint32_t bypass_count;
    const uint32_t *bypass_uids;
    uint32_t cache_count;
    const struct AeCacheBinding *caches;
};

#ifdef __cplusplus
extern "C" {
#endif
AE_EXPORT int ae_policy_valid(const struct AePolicy *policy);
// Caller publishes only validated immutable policies and owns their lifetime.
// Application does no allocation, file access, IPC or complete-list scan.
AE_EXPORT enum AeDecision ae_policy_apply(const struct AePolicy *policy,
                                          uint64_t instance_id,
                                          uint64_t now_ms,
                                          struct AeContext *context);
#ifdef __cplusplus
}
#endif
