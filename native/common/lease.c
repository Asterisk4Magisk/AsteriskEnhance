// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0

#include "lease.h"

int ae_lease_valid(const struct AeLease *lease, uint64_t now) {
    return lease && lease->active && lease->deadline >= AE_LEASE_MILLISECONDS &&
           now >= lease->deadline - AE_LEASE_MILLISECONDS && now < lease->deadline;
}
int ae_lease_activate(struct AeLease *lease,
                      uint64_t connection,
                      uint64_t instance,
                      uint64_t cycle,
                      uint64_t generation,
                      uint64_t now) {
    if (!lease || !connection || !instance || !cycle || !generation ||
        now > UINT64_MAX - AE_LEASE_MILLISECONDS || ae_lease_valid(lease, now))
        return 0;
    lease->connection = connection;
    lease->instance = instance;
    lease->cycle = cycle;
    lease->generation = generation;
    lease->deadline = now + AE_LEASE_MILLISECONDS;
    lease->active = 1;
    return 1;
}
int ae_lease_renew(struct AeLease *lease,
                   uint64_t connection,
                   uint64_t instance,
                   uint64_t cycle,
                   uint64_t generation,
                   uint64_t now) {
    if (!ae_lease_valid(lease, now) || lease->connection != connection ||
        lease->instance != instance || lease->cycle != cycle || lease->generation != generation ||
        now > UINT64_MAX - AE_LEASE_MILLISECONDS)
        return 0;
    lease->deadline = now + AE_LEASE_MILLISECONDS;
    return 1;
}
void ae_lease_revoke(struct AeLease *lease) {
    if (lease) {
        lease->active = 0;
        lease->deadline = 0;
    }
}
