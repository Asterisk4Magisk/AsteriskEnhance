// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0

#include "authority.h"
int ae_peer_is_authority(const struct AePeerIdentity *caller,
                         const struct AePeerIdentity *listener) {
    return caller && listener && caller->uid == 0 && listener->uid == 0 && caller->pid > 1 &&
           caller->pid <= INT32_MAX && caller->pid == listener->pid;
}
