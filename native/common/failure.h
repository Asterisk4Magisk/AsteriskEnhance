// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0
#pragma once
#include <stdint.h>

enum AeFailureStage {
    AE_FAIL_NONE, AE_FAIL_DISCOVER, AE_FAIL_READ, AE_FAIL_RESERVE,
    AE_FAIL_CONFIGURE, AE_FAIL_CHECK, AE_FAIL_ROUTES, AE_FAIL_RELEASE
};
enum AeFailureReason {
    AE_REASON_NONE, AE_REASON_NOT_READY, AE_REASON_CHANGED, AE_REASON_PRIVATE_DNS,
    AE_REASON_NAT64, AE_REASON_INVALID_CONFIG, AE_REASON_BACKEND, AE_REASON_CAPACITY
};
// No addresses, domains, UIDs or configuration contents cross this boundary.
struct AeFailure { uint32_t stage, reason; int32_t error; uint32_t network; };
