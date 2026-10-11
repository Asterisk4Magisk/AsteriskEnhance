// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0

#pragma once
#include "policy.h"
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif
AE_EXPORT size_t ae_store_size(void);
AE_EXPORT void ae_store_init(void *store);
// Single background writer. A busy inactive slot returns 0; never blocks a
// resolver thread. Arrays are copied before atomic publication.
AE_EXPORT int ae_store_publish(void *store, const struct AePolicy *policy);
AE_EXPORT enum AeDecision
ae_store_apply(void *store, uint64_t instance, uint64_t now_ms, struct AeContext *context);
typedef int (*AeSelectionObserver)(void *opaque, uint64_t generation, uint32_t cache_id);
AE_EXPORT enum AeDecision ae_store_apply_observed(void *store,
                                                  uint64_t instance,
                                                  uint64_t now_ms,
                                                  struct AeContext *context,
                                                  AeSelectionObserver observer,
                                                  void *opaque);
AE_EXPORT void ae_store_revoke(void *store);
AE_EXPORT int ae_store_has_active(void *store);
AE_EXPORT int ae_store_quiescent(void *store);
AE_EXPORT void *ae_store_global(void);
#ifdef __cplusplus
}
#endif
