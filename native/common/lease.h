// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0

#pragma once
#include "policy.h"

#define AE_LEASE_MILLISECONDS 3000U
#define AE_RENEW_MILLISECONDS 1000U
#define AE_CONTROL_TIMEOUT_MILLISECONDS 2000U
struct AeLease {
    uint64_t connection, instance, cycle, generation, deadline;
    uint32_t active;
};
#ifdef __cplusplus
extern "C" {
#endif
AE_EXPORT int ae_lease_activate(struct AeLease *,
                                uint64_t connection,
                                uint64_t instance,
                                uint64_t cycle,
                                uint64_t generation,
                                uint64_t now_ms);
AE_EXPORT int ae_lease_renew(struct AeLease *,
                             uint64_t connection,
                             uint64_t instance,
                             uint64_t cycle,
                             uint64_t generation,
                             uint64_t now_ms);
AE_EXPORT int ae_lease_valid(const struct AeLease *, uint64_t now_ms);
AE_EXPORT void ae_lease_revoke(struct AeLease *);
#ifdef __cplusplus
}
#endif
