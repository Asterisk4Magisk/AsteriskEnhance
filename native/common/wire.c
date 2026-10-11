// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0

#include "wire.h"

static uint64_t little_read(const uint8_t *bytes, unsigned width) {
    uint64_t value = 0;
    for (unsigned i = 0; i < width; ++i)
        value |= (uint64_t)bytes[i] << (8 * i);
    return value;
}
static void little_write(uint8_t *bytes, unsigned width, uint64_t value) {
    for (unsigned i = 0; i < width; ++i)
        bytes[i] = (uint8_t)(value >> (8 * i));
}
static int header_valid(const struct AeWireHeader *header) {
    if (!header || header->opcode < AE_HELLO || header->opcode > AE_INFO_REPLY ||
        header->body_length > AE_WIRE_MAX_BODY || !header->request_id)
        return 0;
    if (header->opcode == AE_INFO &&
        (header->body_length || header->instance || header->cycle || header->generation))
        return 0;
    if (header->opcode == AE_INFO_REPLY &&
        (!header->body_length || header->body_length > 512 || header->instance || header->cycle ||
         header->generation))
        return 0;
    if (header->opcode >= AE_PREPARE && header->opcode <= AE_RELEASE &&
        (!header->instance || !header->cycle || !header->generation))
        return 0;
    if ((header->opcode == AE_ACTIVATE || header->opcode == AE_RENEW) && header->body_length != 8)
        return 0;
    if ((header->opcode == AE_DEACTIVATE || header->opcode == AE_RELEASE ||
         header->opcode == AE_HELLO) &&
        header->body_length)
        return 0;
    return 1;
}
int ae_wire_decode(const void *memory, size_t length, struct AeWireHeader *output) {
    if (!memory || !output || length != AE_WIRE_HEADER_SIZE)
        return 0;
    const uint8_t *bytes = memory;
    if (little_read(bytes, 4) != AE_WIRE_MAGIC || little_read(bytes + 4, 2) != AE_WIRE_VERSION)
        return 0;
    struct AeWireHeader header;
    header.opcode = (uint16_t)little_read(bytes + 6, 2);
    header.body_length = (uint32_t)little_read(bytes + 8, 4);
    header.request_id = (uint32_t)little_read(bytes + 12, 4);
    header.instance = little_read(bytes + 16, 8);
    header.cycle = little_read(bytes + 24, 8);
    header.generation = little_read(bytes + 32, 8);
    if (!header_valid(&header))
        return 0;
    *output = header;
    return 1;
}
int ae_wire_encode(const struct AeWireHeader *header, void *memory, size_t capacity) {
    if (!memory || capacity < AE_WIRE_HEADER_SIZE || !header_valid(header))
        return 0;
    uint8_t *bytes = memory;
    little_write(bytes, 4, AE_WIRE_MAGIC);
    little_write(bytes + 4, 2, AE_WIRE_VERSION);
    little_write(bytes + 6, 2, header->opcode);
    little_write(bytes + 8, 4, header->body_length);
    little_write(bytes + 12, 4, header->request_id);
    little_write(bytes + 16, 8, header->instance);
    little_write(bytes + 24, 8, header->cycle);
    little_write(bytes + 32, 8, header->generation);
    return 1;
}
