// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0

#include "prepare.h"

struct AePrepareStorage {
    uint32_t uids[AE_MAX_UIDS], bypass[AE_MAX_UIDS], networks[AE_MAX_NETWORKS];
};
static uint32_t read32(const uint8_t *bytes) {
    return (uint32_t)bytes[0] | ((uint32_t)bytes[1] << 8) | ((uint32_t)bytes[2] << 16) |
           ((uint32_t)bytes[3] << 24);
}
static void write32(uint8_t *bytes, uint32_t value) {
    for (unsigned i = 0; i < 4; ++i)
        bytes[i] = (uint8_t)(value >> (8 * i));
}
int ae_prepare_valid(const struct AePrepare *input) {
    if (!input || !input->netd_instance || input->run_mode < AE_TPROXY ||
        input->run_mode > AE_BPF2SOCKS ||
        (input->consumer_version != 1U && input->consumer_version != AE_CONSUMER_VERSION) ||
        !input->entry_port || input->entry_port > 65535 || input->network_count > AE_MAX_NETWORKS ||
        (input->network_count && !input->networks))
        return 0;
    struct AeCacheBinding caches[AE_MAX_NETWORKS];
    // An empty wire list requests live native discovery. Validate the remaining
    // policy with a placeholder binding; the actor validates the real inventory.
    caches[0] = (struct AeCacheBinding){1, 0x40000000U};
    for (uint32_t i = 0; i < input->network_count; ++i) {
        caches[i].network_id = input->networks[i];
        caches[i].cache_id = 0x40000000U + i;
    }
    const struct AePolicy policy = {1,
                                    1,
                                    1,
                                    0,
                                    input->policy_mode,
                                    input->mark_mask,
                                    input->proxy_mark,
                                    input->direct_mark,
                                    input->uid_count,
                                    input->uids,
                                    input->bypass_count,
                                    input->bypass_uids,
                                    input->network_count ? input->network_count : 1,
                                    caches};
    return ae_policy_valid(&policy);
}
size_t ae_prepare_storage_size(void) {
    return sizeof(struct AePrepareStorage);
}
int ae_prepare_decode(const void *memory, size_t length, void *storage, struct AePrepare *output) {
    if (!memory || !storage || !output || length < AE_PREPARE_FIXED_SIZE)
        return 0;
    const uint8_t *bytes = memory;
    const uint32_t uid_count = read32(bytes + 28), bypass_count = read32(bytes + 32),
                   network_count = read32(bytes + 36);
    if (uid_count > AE_MAX_UIDS || bypass_count > AE_MAX_UIDS || network_count > AE_MAX_NETWORKS ||
        length != AE_PREPARE_FIXED_SIZE + 4U * ((size_t)uid_count + bypass_count + network_count))
        return 0;
    struct AePrepareStorage *owned = storage;
    size_t offset = AE_PREPARE_FIXED_SIZE;
    for (uint32_t i = 0; i < uid_count; ++i, offset += 4)
        owned->uids[i] = read32(bytes + offset);
    for (uint32_t i = 0; i < bypass_count; ++i, offset += 4)
        owned->bypass[i] = read32(bytes + offset);
    for (uint32_t i = 0; i < network_count; ++i, offset += 4)
        owned->networks[i] = read32(bytes + offset);
    const struct AePrepare request = {(uint64_t)read32(bytes + 40) |
                                          ((uint64_t)read32(bytes + 44) << 32),
                                      read32(bytes),
                                      read32(bytes + 4),
                                      read32(bytes + 8),
                                      read32(bytes + 12),
                                      read32(bytes + 16),
                                      read32(bytes + 20),
                                      read32(bytes + 24),
                                      uid_count,
                                      owned->uids,
                                      bypass_count,
                                      owned->bypass,
                                      network_count,
                                      owned->networks};
    if (!ae_prepare_valid(&request))
        return 0;
    *output = request;
    return 1;
}
size_t ae_prepare_encode(const struct AePrepare *input, void *memory, size_t capacity) {
    if (!memory || !ae_prepare_valid(input))
        return 0;
    const size_t length = AE_PREPARE_FIXED_SIZE + 4U * ((size_t)input->uid_count +
                                                        input->bypass_count + input->network_count);
    if (capacity < length)
        return 0;
    uint8_t *bytes = memory;
    const uint32_t fields[] = {input->run_mode,
                               input->policy_mode,
                               input->consumer_version,
                               input->entry_port,
                               input->mark_mask,
                               input->proxy_mark,
                               input->direct_mark,
                               input->uid_count,
                               input->bypass_count,
                               input->network_count};
    for (unsigned i = 0; i < 10; ++i)
        write32(bytes + 4 * i, fields[i]);
    write32(bytes + 40, (uint32_t)input->netd_instance);
    write32(bytes + 44, (uint32_t)(input->netd_instance >> 32));
    size_t offset = AE_PREPARE_FIXED_SIZE;
    for (uint32_t i = 0; i < input->uid_count; ++i, offset += 4)
        write32(bytes + offset, input->uids[i]);
    for (uint32_t i = 0; i < input->bypass_count; ++i, offset += 4)
        write32(bytes + offset, input->bypass_uids[i]);
    for (uint32_t i = 0; i < input->network_count; ++i, offset += 4)
        write32(bytes + offset, input->networks[i]);
    return length;
}
