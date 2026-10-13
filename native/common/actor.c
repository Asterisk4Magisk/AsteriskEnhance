// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0

#include "actor.h"
#include "store.h"

struct AeActor {
    void *store;
    struct AeActorBackend backend;
    uint64_t netd_instance, connection;
    struct AeWireHeader key;
    uint32_t phase, auto_release, modes, seed, used_ids, owned_count, discovered, guarded;
    struct AePolicy policy;
    uint32_t uids[AE_MAX_UIDS], bypass[AE_MAX_UIDS];
    struct AeCacheBinding caches[AE_MAX_NETWORKS];
    uint32_t route_count;
    struct AeDnsRoute routes[AE_MAX_DNS_ROUTES];
    struct AeFailure failure;
    uint32_t cleanup_failed;
};
size_t ae_actor_size(void) {
    return sizeof(struct AeActor);
}
int ae_actor_init(void *memory,
                  void *store,
                  uint64_t instance,
                  uint32_t seed,
                  uint32_t modes,
                  const struct AeActorBackend *backend) {
    if (!memory || !store || !instance || (modes & ~7U) || !backend || !backend->create ||
        !backend->check || !backend->destroy || !backend->inflight || !backend->now_ms)
        return 0;
    struct AeActor *actor = memory;
    actor->store = store;
    actor->backend = *backend;
    actor->netd_instance = instance;
    actor->connection = 0;
    actor->key = (struct AeWireHeader){0};
    actor->phase = AE_STATE_IDLE;
    actor->auto_release = 0;
    actor->modes = modes;
    actor->seed = seed & 0xffffU;
    actor->used_ids = 0;
    actor->owned_count = 0;
    actor->discovered = 0;
    actor->guarded = 0;
    actor->policy = (struct AePolicy){0};
    actor->route_count = 0;
    actor->failure = (struct AeFailure){0};
    actor->cleanup_failed = 0;
    return 1;
}
static void failed(struct AeActor *actor, uint32_t stage, uint32_t reason, int error,
                   uint32_t network) {
    actor->failure = actor->backend.failure ? actor->backend.failure(actor->backend.opaque)
                                           : (struct AeFailure){0};
    if (!actor->failure.stage)
        actor->failure = (struct AeFailure){stage, reason, error, network};
}
struct AeFailure ae_actor_failure(const void *memory) {
    return memory ? ((const struct AeActor *)memory)->failure : (struct AeFailure){0};
}
static int key_valid(uint64_t connection, const struct AeWireHeader *key) {
    return connection && key && key->instance && key->cycle && key->generation;
}
static int
key_matches(const struct AeActor *actor, uint64_t connection, const struct AeWireHeader *key) {
    return key_valid(connection, key) && actor->connection == connection &&
           actor->key.instance == key->instance && actor->key.cycle == key->cycle &&
           actor->key.generation == key->generation;
}
static void withdraw(struct AeActor *actor, int automatic) {
    ae_store_revoke(actor->store);
    actor->guarded = 0;
    actor->policy.active = 0;
    actor->phase = AE_STATE_DRAINING;
    actor->cleanup_failed = 0;
    if (automatic)
        actor->auto_release = 1;
}
static enum AeResult release_resources(struct AeActor *actor) {
    actor->cleanup_failed = 0;
    if (!ae_store_quiescent(actor->store) || actor->backend.inflight(actor->backend.opaque))
        return AE_DRAINING;
    uint32_t retained = 0;
    for (uint32_t i = 0; i < actor->owned_count; ++i) {
        if (actor->backend.destroy(actor->backend.opaque, actor->caches[i].cache_id))
            actor->caches[retained++] = actor->caches[i];
    }
    actor->owned_count = retained;
    if (retained) {
        actor->cleanup_failed = 1;
        return AE_CACHE_ERROR;
    }
    actor->phase = AE_STATE_IDLE;
    actor->auto_release = 0;
    return AE_OK;
}
void ae_actor_reap(void *memory) {
    if (!memory)
        return;
    struct AeActor *actor = memory;
    if (actor->phase == AE_STATE_DRAINING && actor->auto_release)
        release_resources(actor);
}
int ae_actor_poll_timeout(const void *memory) {
    const struct AeActor *actor = memory;
    if (!actor)
        return -1;
    // Retained resolver workers may finish without a control-channel event.
    if (actor->phase == AE_STATE_DRAINING && actor->auto_release && !actor->cleanup_failed)
        return 1000;
    return -1;
}
void ae_actor_disconnect(void *memory, uint64_t connection) {
    if (!memory)
        return;
    struct AeActor *actor = memory;
    if (connection && actor->connection == connection)
        withdraw(actor, 1);
}
static int configurations_current(struct AeActor *actor) {
    if (actor->backend.validate)
        return actor->backend.validate(actor->backend.opaque, actor->caches,
                                       actor->owned_count, actor->discovered) == 0;
    if (actor->discovered) {
        uint32_t networks[AE_MAX_NETWORKS];
        const int count = actor->backend.networks(actor->backend.opaque, networks, AE_MAX_NETWORKS);
        if (count < 0 || (uint32_t)count != actor->owned_count)
            return 0;
        for (uint32_t i = 0; i < actor->owned_count; ++i)
            if (networks[i] != actor->caches[i].network_id)
                return 0;
    }
    for (uint32_t i = 0; i < actor->owned_count; ++i) {
        if (actor->backend.check(
                actor->backend.opaque, actor->caches[i].network_id, actor->caches[i].cache_id))
            return 0;
    }
    return 1;
}
enum AeResult ae_actor_prepare(void *memory,
                               uint64_t connection,
                               const struct AeWireHeader *key,
                               const struct AePrepare *input) {
    if (!memory || !key_valid(connection, key) || key->opcode != AE_PREPARE ||
        !ae_prepare_valid(input))
        return AE_INVALID;
    struct AeActor *actor = memory;
    ae_actor_reap(actor);
    actor->failure = (struct AeFailure){0};
    if (input->netd_instance != actor->netd_instance)
        return AE_STALE;
    if (!(actor->modes & (1U << (input->run_mode - 1))) || input->mark_mask != AE_MARK_MASK ||
        input->proxy_mark != AE_PROXY_MARK || input->direct_mark != AE_DIRECT_MARK)
        return AE_UNSUPPORTED;
    if (actor->phase != AE_STATE_IDLE)
        return AE_BUSY;
    const uint32_t discovered = !input->network_count;
    uint32_t networks[AE_MAX_NETWORKS];
    struct AePrepare resolved = *input;
    if (discovered) {
        if (!actor->backend.networks)
            return AE_UNSUPPORTED;
        const int count = actor->backend.networks(actor->backend.opaque, networks, AE_MAX_NETWORKS);
        if (count < 0 || count > (int)AE_MAX_NETWORKS) {
            failed(actor, AE_FAIL_DISCOVER, count == 0 ? AE_REASON_NOT_READY : AE_REASON_BACKEND,
                   count < 0 ? count : 0, 0);
            return AE_CACHE_ERROR;
        }
        resolved.network_count = (uint32_t)count;
        resolved.networks = networks;
        if (!ae_prepare_valid(&resolved)) {
            actor->failure = (struct AeFailure){AE_FAIL_DISCOVER, AE_REASON_INVALID_CONFIG, 0, 0};
            return AE_CACHE_ERROR;
        }
        input = &resolved;
    }
    if ((actor->connection == connection && actor->key.instance &&
         actor->key.instance != key->instance) ||
        (actor->key.instance == key->instance &&
         (key->cycle < actor->key.cycle ||
          (key->cycle == actor->key.cycle && key->generation <= actor->key.generation))))
        return AE_STALE;
    actor->connection = connection;
    actor->key = *key;
    actor->auto_release = 0;
    actor->discovered = discovered;
    actor->route_count = 0;
    for (uint32_t i = 0; i < input->uid_count; ++i)
        actor->uids[i] = input->uids[i];
    for (uint32_t i = 0; i < input->bypass_count; ++i)
        actor->bypass[i] = input->bypass_uids[i];
    actor->policy = (struct AePolicy){actor->netd_instance,
                                      key->generation,
                                      0,
                                      input->policy_mode,
                                      input->mark_mask,
                                      input->proxy_mark,
                                      input->direct_mark,
                                      input->uid_count,
                                      actor->uids,
                                      input->bypass_count,
                                      actor->bypass,
                                      input->network_count,
                                      actor->caches};
    enum AeResult error = AE_OK;
    for (uint32_t i = 0; i < input->network_count && error == AE_OK; ++i) {
        int created = 0;
        for (unsigned attempt = 0; attempt < 32 && !created; ++attempt) {
            if (actor->used_ids >= 0x10000U) {
                error = AE_EXHAUSTED;
                break;
            }
            const uint32_t id = 0x40000000U + ((actor->seed + actor->used_ids++) & 0xffffU);
            uint32_t owned = 0;
            const int result =
                actor->backend.create(actor->backend.opaque, input->networks[i], id, &owned);
            if (owned)
                actor->caches[actor->owned_count++] =
                    (struct AeCacheBinding){input->networks[i], id};
            if (result == 0 && owned == 1)
                created = 1;
            else if (result != 1 || owned) {
                failed(actor, AE_FAIL_RESERVE, AE_REASON_BACKEND, result, input->networks[i]);
                error = AE_CACHE_ERROR;
                break;
            }
        }
        if (!created && error == AE_OK)
            error = AE_BUSY;
    }
    if (error == AE_OK && input->consumer_version >= 2U) {
        if (!actor->backend.routes)
            error = AE_UNSUPPORTED;
        for (uint32_t i = 0; i < actor->owned_count && error == AE_OK; ++i) {
            const uint32_t remaining = AE_MAX_DNS_ROUTES - actor->route_count;
            const struct AeCacheBinding *binding = &actor->caches[i];
            struct AeDnsRoute *routes = actor->routes + actor->route_count;
            const int count = remaining ? actor->backend.routes(actor->backend.opaque,
                                                                binding->network_id,
                                                                binding->cache_id,
                                                                routes,
                                                                remaining)
                                        : -1;
            if (count < 1 || (uint32_t)count > remaining) {
                failed(actor, AE_FAIL_ROUTES, AE_REASON_BACKEND, count, binding->network_id);
                error = AE_CACHE_ERROR;
                break;
            }
            for (int j = 0; j < count; ++j) {
                const struct AeDnsRoute *route = &routes[j];
                if (route->network_id != binding->network_id ||
                    (route->original_mark & AE_MARK_MASK) ||
                    (route->family != 4U && route->family != 6U) ||
                    (route->family == 4U && route->scope_id))
                    error = AE_CACHE_ERROR;
                if (route->family == 4U)
                    for (unsigned k = 4; k < 16; ++k)
                        if (route->address[k])
                            error = AE_CACHE_ERROR;
            }
            actor->route_count += (uint32_t)count;
            if (error != AE_OK)
                actor->failure = (struct AeFailure){AE_FAIL_ROUTES, AE_REASON_INVALID_CONFIG, 0,
                                                   binding->network_id};
        }
    }
    if (error != AE_OK) {
        actor->route_count = 0;
        if (actor->guarded) {
            actor->phase = AE_STATE_DRAINING;
            actor->auto_release = 0;
        } else withdraw(actor, 0);
        release_resources(actor); // Retain failed deletions for RELEASE/disconnect.
        return error;
    }
    actor->phase = AE_STATE_PREPARED;
    return AE_OK;
}
enum AeResult
ae_actor_control(void *memory, uint64_t connection, const struct AeWireHeader *key, uint64_t now) {
    return ae_actor_control_until(memory, connection, key, now, UINT64_MAX);
}
enum AeResult ae_actor_control_until(void *memory,
                                     uint64_t connection,
                                     const struct AeWireHeader *key,
                                     uint64_t now,
                                     uint64_t request_deadline) {
    if (!memory || !key_valid(connection, key) || key->opcode < AE_ACTIVATE ||
        key->opcode > AE_RELEASE || key->body_length)
        return AE_INVALID;
    struct AeActor *actor = memory;
    ae_actor_reap(actor);
    if (now >= request_deadline)
        return AE_STALE;
    if (!key_matches(actor, connection, key))
        return AE_STALE;
    if (key->opcode == AE_DEACTIVATE) {
        if (actor->phase == AE_STATE_IDLE) {
            ae_store_revoke(actor->store); // Automatic drain may retain a waiting guard.
            actor->guarded = 0;
            return AE_OK; // Exact identity already withdrew and drained.
        }
        withdraw(actor, 0);
        return AE_OK;
    }
    if (key->opcode == AE_RELEASE) {
        if (actor->phase == AE_STATE_ACTIVE || actor->phase == AE_STATE_PREPARED)
            return AE_BUSY;
        return actor->phase == AE_STATE_IDLE ? AE_OK : release_resources(actor);
    }
    const int activating = key->opcode == AE_ACTIVATE;
    if ((activating && actor->phase != AE_STATE_PREPARED) ||
        (!activating && actor->phase != AE_STATE_ACTIVE))
        return AE_STALE;
    if (!configurations_current(actor)) {
        // Preserve UID decisions while rebuilding: selected queries must not
        // fall back to a shared resolver cache when their network disappears.
        struct AePolicy guard = actor->policy;
        guard.active = 1;
        guard.cache_count = 0;
        if (!ae_store_publish(actor->store, &guard))
            return AE_BUSY;
        actor->guarded = 1;
        actor->phase = AE_STATE_DRAINING;
        actor->auto_release = 1;
        return AE_CACHE_ERROR;
    }
    // Configuration checks can block in Binder; honor the caller's request budget.
    now = actor->backend.now_ms(actor->backend.opaque);
    if (now >= request_deadline) {
        withdraw(actor, 1);
        return AE_STALE;
    }
    if (!activating)
        return AE_OK;
    struct AePolicy policy = actor->policy;
    policy.active = 1;
    if (!ae_store_publish(actor->store, &policy))
        return AE_BUSY;
    actor->policy = policy;
    actor->guarded = policy.cache_count == 0;
    actor->phase = AE_STATE_ACTIVE;
    return AE_OK;
}
uint32_t ae_actor_phase(const void *memory) {
    return memory ? ((const struct AeActor *)memory)->phase : AE_STATE_IDLE;
}
uint32_t ae_actor_resource_count(const void *memory) {
    return memory ? ((const struct AeActor *)memory)->owned_count : 0;
}
uint32_t ae_actor_routes(const void *memory, struct AeDnsRoute *output, uint32_t capacity) {
    if (!memory || !output)
        return 0;
    const struct AeActor *actor = memory;
    if (actor->phase != AE_STATE_PREPARED || actor->route_count > capacity)
        return 0;
    for (uint32_t i = 0; i < actor->route_count; ++i)
        output[i] = actor->routes[i];
    return actor->route_count;
}
