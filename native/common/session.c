// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0

#include "session.h"
struct AeSession {
    void *actor;
    uint64_t netd_instance, connection, owner;
    uint32_t api, modes, flags, last_request;
    uint32_t storage[AE_MAX_UIDS * 2 + AE_MAX_NETWORKS];
};
static void put(uint8_t *bytes, uint64_t value, unsigned width) {
    for (unsigned i = 0; i < width; ++i)
        bytes[i] = (uint8_t)(value >> (8 * i));
}
size_t ae_session_size(void) {
    return sizeof(struct AeSession);
}
int ae_session_init(
    void *memory, void *actor, uint64_t instance, uint32_t api, uint32_t modes, uint32_t flags) {
    if (!memory || !actor || !instance || !api || (modes & ~7U) ||
        (flags & ~(AE_CAP_NETWORK_DISCOVERY | AE_CAP_DNS_ROUTES)))
        return 0;
    struct AeSession *session = memory;
    session->actor = actor;
    session->netd_instance = instance;
    session->api = api;
    session->modes = modes;
    session->flags = flags;
    session->connection = 0;
    session->owner = 0;
    session->last_request = 0;
    return 1;
}
void ae_session_close(void *memory) {
    if (!memory)
        return;
    struct AeSession *session = memory;
    ae_actor_disconnect(session->actor, session->connection);
    session->connection = 0;
    session->owner = 0;
    session->last_request = 0;
}
void ae_session_open(void *memory, uint64_t connection) {
    if (!memory)
        return;
    ae_session_close(memory);
    ((struct AeSession *)memory)->connection = connection;
}
size_t ae_session_handle(void *memory,
                         const struct AeWireHeader *key,
                         const void *body,
                         size_t length,
                         uint64_t now,
                         void *output,
                         size_t capacity) {
    return ae_session_handle_until(memory, key, body, length, now, UINT64_MAX, output, capacity);
}
size_t ae_session_handle_until(void *memory,
                               const struct AeWireHeader *key,
                               const void *body,
                               size_t length,
                               uint64_t now,
                               uint64_t request_deadline,
                               void *output,
                               size_t capacity) {
    if (!memory || !key || !output || capacity < AE_RESPONSE_MAX_SIZE || (length && !body))
        return 0;
    struct AeSession *session = memory;
    uint8_t scratch[AE_WIRE_HEADER_SIZE];
    if (!ae_wire_encode(key, scratch, sizeof(scratch)) || key->body_length != length ||
        !session->connection)
        return 0;
    if (key->opcode == AE_ACTIVATE || key->opcode == AE_CHECK) {
        const uint8_t *bytes = body;
        uint64_t caller_deadline = 0;
        for (unsigned i = 0; i < 8; ++i)
            caller_deadline |= (uint64_t)bytes[i] << (8 * i);
        if (caller_deadline < request_deadline)
            request_deadline = caller_deadline;
    }
    enum AeResult result = AE_OK;
    int capabilities = 0;
    uint32_t route_count = 0;
    struct AeDnsRoute routes[AE_MAX_DNS_ROUTES];
    if (now >= request_deadline || key->request_id <= session->last_request || !key->instance ||
        (session->owner && key->instance != session->owner))
        result = AE_STALE;
    else {
        session->last_request = key->request_id;
        if (key->opcode == AE_HELLO) {
            session->owner = key->instance;
            capabilities = 1;
        } else if (!session->owner)
            result = AE_STALE;
        else if (key->opcode == AE_PREPARE) {
            struct AePrepare prepared;
            if (ae_prepare_storage_size() > sizeof(session->storage) ||
                !ae_prepare_decode(body, length, session->storage, &prepared))
                result = AE_INVALID;
            else if (prepared.consumer_version != AE_CONSUMER_VERSION)
                result = AE_UNSUPPORTED;
            else {
                result = ae_actor_prepare(session->actor, session->connection, key, &prepared);
                if (result == AE_OK && prepared.consumer_version == 2U)
                    route_count = ae_actor_routes(session->actor, routes, AE_MAX_DNS_ROUTES);
            }
        } else if (key->opcode >= AE_ACTIVATE && key->opcode <= AE_RELEASE) {
            struct AeWireHeader control = *key;
            control.body_length = 0; // Actor receives the validated absolute deadline separately.
            result = ae_actor_control_until(
                session->actor, session->connection, &control, now, request_deadline);
        } else
            result = AE_INVALID;
    }
    struct AeWireHeader reply = *key;
    reply.opcode = capabilities ? AE_CAPABILITIES : result == AE_OK ? AE_ACK : AE_ERROR;
    reply.body_length = capabilities ? AE_CAPABILITIES_SIZE : AE_RESULT_SIZE;
    if (route_count)
        reply.body_length += 4U + route_count * 32U;
    if (!ae_wire_encode(&reply, output, capacity))
        return 0;
    uint8_t *bytes = (uint8_t *)output + AE_WIRE_HEADER_SIZE;
    put(bytes, session->netd_instance, 8);
    if (capabilities) {
        const uint32_t values[] = {5,
                                   session->api,
                                   session->modes,
                                   AE_MARK_MASK,
                                   AE_PROXY_MARK,
                                   AE_DIRECT_MARK,
                                   AE_CONSUMER_VERSION,
                                   0,
                                   0,
                                   session->flags};
        for (unsigned i = 0; i < 10; ++i)
            put(bytes + 8 + i * 4, values[i], 4);
    } else {
        put(bytes + 8, result, 4);
        put(bytes + 12, ae_actor_phase(session->actor), 4);
        put(bytes + 16, ae_actor_resource_count(session->actor), 4);
        put(bytes + 20, 0, 4);
        if (route_count) {
            put(bytes + 24, route_count, 4);
            for (uint32_t i = 0; i < route_count; ++i) {
                uint8_t *entry = bytes + 28U + i * 32U;
                put(entry, routes[i].network_id, 4);
                put(entry + 4, routes[i].original_mark, 4);
                put(entry + 8, routes[i].family, 4);
                put(entry + 12, routes[i].scope_id, 4);
                for (unsigned j = 0; j < 16; ++j)
                    entry[16 + j] = routes[i].address[j];
            }
        }
    }
    return AE_WIRE_HEADER_SIZE + reply.body_length;
}
