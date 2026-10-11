// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0

#pragma once
#include "prepare.h"
#include "wire.h"

enum AeResult {
    AE_OK = 0,
    AE_INVALID = 1,
    AE_UNSUPPORTED = 2,
    AE_STALE = 3,
    AE_BUSY = 4,
    AE_CACHE_ERROR = 5,
    AE_DRAINING = 6,
    AE_EXHAUSTED = 7,
    AE_IO_ERROR = 8
};
enum AePhase {
    AE_STATE_IDLE = 0,
    AE_STATE_PREPARED = 1,
    AE_STATE_ACTIVE = 2,
    AE_STATE_DRAINING = 3
};
#define AE_MARK_MASK 0x61000000U
#define AE_PROXY_MARK 0x01000000U
#define AE_DIRECT_MARK 0x41000000U
#define AE_MAX_DNS_ROUTES 64U
struct AeDnsRoute {
    uint32_t network_id, original_mark, family, scope_id;
    uint8_t address[16];
};
struct AeActorBackend {
    void *opaque;
    // create: 0 success, 1 collision, other failure. owned is set immediately
    // after exclusive reservation, even if subsequent configuration fails.
    int (*create)(void *, uint32_t network_id, uint32_t cache_id, uint32_t *owned);
    int (*check)(void *, uint32_t network_id, uint32_t cache_id);
    int (*destroy)(void *, uint32_t cache_id);
    uint32_t (*inflight)(void *);
    uint64_t (*now_ms)(void *); // CLOCK_BOOTTIME; UINT64_MAX on clock failure.
    // Sorted original resolver networks; count on success, negative on error.
    // Optional for an explicit network list; required for discovery.
    int (*networks)(void *, uint32_t *, uint32_t capacity);
    // Exact original config/mark for one already reserved network/cache pair.
    int (*routes)(
        void *, uint32_t network_id, uint32_t cache_id, struct AeDnsRoute *, uint32_t capacity);
};
// All actor methods run on one background writer. Resolver readers use store.
#ifdef __cplusplus
extern "C" {
#endif
AE_EXPORT size_t ae_actor_size(void);
AE_EXPORT int ae_actor_init(void *,
                            void *store,
                            uint64_t netd_instance,
                            uint32_t seed,
                            uint32_t modes,
                            const struct AeActorBackend *);
AE_EXPORT enum AeResult ae_actor_prepare(void *,
                                         uint64_t connection,
                                         const struct AeWireHeader *,
                                         const struct AePrepare *,
                                         uint64_t now_ms);
AE_EXPORT enum AeResult
ae_actor_control(void *, uint64_t connection, const struct AeWireHeader *, uint64_t now_ms);
AE_EXPORT enum AeResult ae_actor_control_until(void *,
                                               uint64_t connection,
                                               const struct AeWireHeader *,
                                               uint64_t now_ms,
                                               uint64_t request_deadline);
AE_EXPORT void ae_actor_disconnect(void *, uint64_t connection);
AE_EXPORT void ae_actor_tick(void *, uint64_t now_ms);
AE_EXPORT uint32_t ae_actor_phase(const void *);
AE_EXPORT uint32_t ae_actor_resource_count(const void *);
AE_EXPORT uint32_t ae_actor_routes(const void *, struct AeDnsRoute *, uint32_t capacity);
#ifdef __cplusplus
}
#endif
