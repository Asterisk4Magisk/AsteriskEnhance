// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0

#pragma once
#include "policy.h"
struct AePeerIdentity {
    uint32_t uid, pid;
};
#ifdef __cplusplus
extern "C" {
#endif
AE_EXPORT int ae_peer_is_authority(const struct AePeerIdentity *caller,
                                   const struct AePeerIdentity *control_listener);
#ifdef __cplusplus
}
#endif
