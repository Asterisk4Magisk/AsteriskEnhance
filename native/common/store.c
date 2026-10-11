// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0

#include "store.h"

#include <stdatomic.h>

#define AE_STORE_EMPTY UINT32_MAX
struct AeOwnedPolicy {
    struct AePolicy policy;
    uint32_t uids[8192], bypass[8192];
    struct AeCacheBinding caches[64];
};
struct AeStore {
    _Atomic uint32_t active;
    _Atomic uint32_t readers[2];
    struct AeOwnedPolicy slots[2];
};
static struct AeStore global_store = {.active = AE_STORE_EMPTY};
size_t ae_store_size(void) {
    return sizeof(struct AeStore);
}
void *ae_store_global(void) {
    return &global_store;
}
void ae_store_init(void *memory) {
    if (!memory)
        return;
    struct AeStore *store = memory;
    atomic_init(&store->active, AE_STORE_EMPTY);
    atomic_init(&store->readers[0], 0);
    atomic_init(&store->readers[1], 0);
}
int ae_store_has_active(void *memory) {
    if (!memory)
        return 0;
    struct AeStore *store = memory;
    return atomic_load_explicit(&store->active, memory_order_seq_cst) != AE_STORE_EMPTY;
}
int ae_store_publish(void *memory, const struct AePolicy *policy) {
    if (!memory || !ae_policy_valid(policy))
        return 0;
    struct AeStore *store = memory;
    const uint32_t active = atomic_load_explicit(&store->active, memory_order_seq_cst);
    const uint32_t target = active == AE_STORE_EMPTY ? 0U : active ^ 1U;
    if (atomic_load_explicit(&store->readers[target], memory_order_seq_cst))
        return 0;
    struct AeOwnedPolicy *slot = &store->slots[target];
    slot->policy = *policy;
    for (uint32_t i = 0; i < policy->uid_count; ++i)
        slot->uids[i] = policy->uids[i];
    for (uint32_t i = 0; i < policy->bypass_count; ++i)
        slot->bypass[i] = policy->bypass_uids[i];
    for (uint32_t i = 0; i < policy->cache_count; ++i)
        slot->caches[i] = policy->caches[i];
    slot->policy.uids = slot->uids;
    slot->policy.bypass_uids = slot->bypass;
    slot->policy.caches = slot->caches;
    atomic_store_explicit(&store->active, target, memory_order_seq_cst);
    return 1;
}
enum AeDecision ae_store_apply_observed(void *memory,
                                        uint64_t instance,
                                        struct AeContext *context,
                                        AeSelectionObserver observer,
                                        void *opaque) {
    if (!memory)
        return AE_ORIGINAL;
    struct AeStore *store = memory;
    for (unsigned attempt = 0; attempt < 32; ++attempt) {
        const uint32_t slot = atomic_load_explicit(&store->active, memory_order_seq_cst);
        if (slot == AE_STORE_EMPTY)
            return AE_ORIGINAL;
        atomic_fetch_add_explicit(&store->readers[slot], 1, memory_order_seq_cst);
        if (atomic_load_explicit(&store->active, memory_order_seq_cst) != slot) {
            atomic_fetch_sub_explicit(&store->readers[slot], 1, memory_order_seq_cst);
            continue;
        }
        const uint32_t original_netid = context ? context->dns_netid : 0;
        const uint32_t original_mark = context ? context->dns_mark : 0;
        enum AeDecision result = ae_policy_apply(&store->slots[slot].policy, instance, context);
        if (result == AE_PROXY && observer &&
            !observer(opaque, store->slots[slot].policy.generation, context->dns_netid)) {
            context->dns_netid = original_netid;
            context->dns_mark = original_mark;
            result = AE_ORIGINAL;
        }
        atomic_fetch_sub_explicit(&store->readers[slot], 1, memory_order_seq_cst);
        return result;
    }
    return AE_ORIGINAL;
}
enum AeDecision ae_store_apply(void *memory, uint64_t instance, struct AeContext *context) {
    return ae_store_apply_observed(memory, instance, context, 0, 0);
}
int ae_store_quiescent(void *memory) {
    if (!memory)
        return 1;
    struct AeStore *store = memory;
    return !atomic_load_explicit(&store->readers[0], memory_order_seq_cst) &&
           !atomic_load_explicit(&store->readers[1], memory_order_seq_cst);
}
void ae_store_revoke(void *memory) {
    if (memory) {
        struct AeStore *store = memory;
        atomic_store_explicit(&store->active, AE_STORE_EMPTY, memory_order_seq_cst);
    }
}
