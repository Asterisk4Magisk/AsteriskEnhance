// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0

#pragma once
#include <stdint.h>
#include "zygisk_next_api.h"

bool ae_query_install(const ZygiskNextAPI *api, const char *image_path, int sdk);
bool ae_query_tracking_ready();
bool ae_query_in_command();
int ae_query_observe(void *, uint64_t generation, uint32_t cache_id);
uint32_t ae_query_inflight();
// Arms one ae_runtime_drained() call for when no tracked query remains.
void ae_query_wait_drain();
