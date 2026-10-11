// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0

#include "policy.h"
#include <stddef.h>

#define AE_MAX_UIDS 8192U
#define AE_MAX_NETWORKS 64U
#define AE_SYSTEM_MARK_MASK 0x001fffffU

static int sorted_uids(const uint32_t *uids, uint32_t count) {
    if (count > AE_MAX_UIDS || (count && !uids))
        return 0;
    for (uint32_t i = 0; i < count; ++i) {
        if (uids[i] == UINT32_MAX || (i && uids[i - 1] >= uids[i]))
            return 0;
    }
    return 1;
}

int ae_policy_valid(const struct AePolicy *policy) {
    if (!policy || !policy->instance_id || !policy->generation || policy->active > 1 ||
        policy->mode < AE_WHITELIST || policy->mode > AE_GLOBAL || !policy->mark_mask ||
        (policy->mark_mask & AE_SYSTEM_MARK_MASK) || !policy->proxy_mark || !policy->direct_mark ||
        policy->proxy_mark == policy->direct_mark || (policy->proxy_mark & ~policy->mark_mask) ||
        (policy->direct_mark & ~policy->mark_mask) ||
        !sorted_uids(policy->uids, policy->uid_count) ||
        !sorted_uids(policy->bypass_uids, policy->bypass_count) || !policy->cache_count ||
        policy->cache_count > AE_MAX_NETWORKS || !policy->caches)
        return 0;
    for (uint32_t i = 0; i < policy->cache_count; ++i) {
        const struct AeCacheBinding *entry = &policy->caches[i];
        if (!entry->network_id || entry->network_id > 0xffffU || entry->cache_id <= 0xffffU ||
            entry->cache_id > INT32_MAX ||
            (i && policy->caches[i - 1].network_id >= entry->network_id))
            return 0;
        for (uint32_t j = 0; j < i; ++j)
            if (policy->caches[j].cache_id == entry->cache_id)
                return 0;
    }
    return 1;
}

static int contains(const uint32_t *values, uint32_t count, uint32_t uid) {
    uint32_t first = 0, last = count;
    while (first < last) {
        uint32_t middle = first + (last - first) / 2;
        if (values[middle] < uid)
            first = middle + 1;
        else
            last = middle;
    }
    return first < count && values[first] == uid;
}

enum AeDecision
ae_policy_apply(const struct AePolicy *policy, uint64_t instance_id, struct AeContext *context) {
    if (!policy || !context || !policy->active || policy->instance_id != instance_id ||
        context->uid == UINT32_MAX)
        return AE_ORIGINAL;
    if (context->dns_mark & policy->mark_mask)
        return AE_MARK_CONFLICT;
    const int bypass = contains(policy->bypass_uids, policy->bypass_count, context->uid);
    const int listed = contains(policy->uids, policy->uid_count, context->uid);
    const int selected =
        !bypass && (policy->mode == AE_GLOBAL || (policy->mode == AE_WHITELIST ? listed : !listed));
    uint32_t cache = 0;
    if (selected) {
        for (uint32_t i = 0; i < policy->cache_count; ++i) {
            if (policy->caches[i].network_id == context->dns_netid) {
                cache = policy->caches[i].cache_id;
                break;
            }
        }
        if (!cache)
            return AE_CACHE_MISSING;
    }
    if (selected)
        context->dns_netid = cache;
    context->dns_mark = (context->dns_mark & ~policy->mark_mask) |
                        (selected ? policy->proxy_mark : policy->direct_mark);
    return selected ? AE_PROXY : AE_DIRECT;
}
