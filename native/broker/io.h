// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0

#pragma once
#include "../common/wire.h"
#include <vector>
uint64_t ae_now_ms();
bool ae_io(int fd, void *bytes, size_t length, bool sending, uint64_t deadline);
bool ae_read_frame(int fd, AeWireHeader *, std::vector<uint8_t> *, uint64_t deadline);
bool ae_write_frame(int fd, const AeWireHeader &, std::vector<uint8_t> &, uint64_t deadline);
int ae_abstract_listener(const char *name);
// Private envelope on the Zygisk Next supplied channel, little endian.
// Zero connection means invalid. Public clients cannot supply this identity.
bool ae_envelope(int fd, uint64_t *connection, bool *disconnect, bool sending, uint64_t *deadline);
