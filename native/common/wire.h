// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0

#pragma once
#include "policy.h"
#include <stddef.h>

#define AE_WIRE_MAGIC 0x314e4541U
#define AE_WIRE_VERSION 1U
#define AE_WIRE_HEADER_SIZE 40U
#define AE_WIRE_MAX_BODY 1048576U
enum AeOpcode {
    AE_HELLO = 1,
    AE_PREPARE = 2,
    AE_ACTIVATE = 3,
    AE_RENEW = 4,
    AE_DEACTIVATE = 5,
    AE_RELEASE = 6,
    AE_ACK = 7,
    AE_ERROR = 8,
    AE_CAPABILITIES = 9,
    AE_INFO = 10,
    AE_INFO_REPLY = 11
};
struct AeWireHeader {
    uint16_t opcode;
    uint32_t body_length, request_id;
    uint64_t instance, cycle, generation;
};
#ifdef __cplusplus
extern "C" {
#endif
AE_EXPORT int ae_wire_decode(const void *bytes, size_t length, struct AeWireHeader *output);
AE_EXPORT int ae_wire_encode(const struct AeWireHeader *header, void *bytes, size_t capacity);
#ifdef __cplusplus
}
#endif
