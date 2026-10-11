// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0

#include "query_lifetime.h"
#include <atomic>
#include <cerrno>
#include <cstddef>
#include <cstdio>
#include <pthread.h>

namespace {
using Command = int (*)(void *, void *, int, char **);
using Routine = void *(*)(void *);
using Create = int (*)(pthread_t *, const pthread_attr_t *, Routine, void *);
Command commands[4]{};
Create original_create = nullptr;
Routine allowed_routines[8]{};
unsigned routine_count = 0;
bool track_command_threads = false;
std::atomic<bool> ready{false};
std::atomic<uint32_t> inflight{0}, cursor{0};
thread_local unsigned command_depth = 0;
thread_local uint64_t selected_generation = 0;
struct Slot {
    std::atomic<bool> busy{false};
    Routine routine = nullptr;
    void *argument = nullptr;
};
Slot slots[2048];

int run_command(unsigned index, void *self, void *client, int argc, char **argv) {
    ++command_depth;
    const int result = commands[index](self, client, argc, argv);
    --command_depth;
    if (!command_depth && selected_generation) {
        selected_generation = 0;
        inflight.fetch_sub(1);
    }
    return result;
}
int command0(void *s, void *c, int n, char **a) {
    return run_command(0, s, c, n, a);
}
int command1(void *s, void *c, int n, char **a) {
    return run_command(1, s, c, n, a);
}
int command2(void *s, void *c, int n, char **a) {
    return run_command(2, s, c, n, a);
}
int command3(void *s, void *c, int n, char **a) {
    return run_command(3, s, c, n, a);
}

void *tracked_start(void *pointer) {
    auto *slot = static_cast<Slot *>(pointer);
    const Routine routine = slot->routine;
    void *argument = slot->argument;
    void *result = routine(argument); // Includes handler destruction and TCP retries.
    inflight.fetch_sub(1);
    slot->busy.store(false, std::memory_order_release);
    return result;
}
int create_thread(pthread_t *thread, const pthread_attr_t *attrs, Routine routine, void *argument) {
    bool allowed = track_command_threads;
    for (unsigned i = 0; i < routine_count; ++i)
        if (routine == allowed_routines[i])
            allowed = true;
    if (!selected_generation || !command_depth || !allowed)
        return original_create(thread, attrs, routine, argument);
    Slot *slot = nullptr;
    const uint32_t start = cursor.fetch_add(1);
    for (unsigned i = 0; i < 2048; ++i) {
        auto &candidate = slots[(start + i) % 2048];
        bool expected = false;
        if (candidate.busy.compare_exchange_strong(expected, true, std::memory_order_acq_rel)) {
            slot = &candidate;
            break;
        }
    }
    if (!slot)
        return EAGAIN; // Original launch failure path releases the pending reference.
    slot->routine = routine;
    slot->argument = argument;
    if (track_command_threads)
        inflight.fetch_add(1); // Keep the command reference until it returns.
    else
        selected_generation = 0; // Transfer the command's existing reference to the worker.
    const int result = original_create(thread, attrs, tracked_start, slot);
    if (result) {
        inflight.fetch_sub(1);
        slot->busy.store(false, std::memory_order_release);
    }
    return result;
}
} // namespace

bool ae_query_tracking_ready() {
    return ready.load();
}
bool ae_query_in_command() {
    return ready.load() && command_depth != 0;
}
uint32_t ae_query_inflight() {
    return inflight.load();
}
int ae_query_observe(void *, uint64_t generation, uint32_t) {
    if (!ae_query_in_command() || !generation)
        return 0;
    if (!selected_generation)
        inflight.fetch_add(1);
    selected_generation = generation;
    return 1;
}

bool ae_query_install(const ZygiskNextAPI *api, const char *path, int sdk) {
    if (ready.load())
        return true;
    auto *symbols = api->newSymbolResolver(path, nullptr);
    if (!symbols)
        return false;
    const char *names[] = {
        "_ZN7android3net16DnsProxyListener14GetAddrInfoCmd10runCommandEP12SocketClientiPPc",
        "_ZN7android3net16DnsProxyListener16GetHostByNameCmd10runCommandEP12SocketClientiPPc",
        "_ZN7android3net16DnsProxyListener16GetHostByAddrCmd10runCommandEP12SocketClientiPPc",
        "_ZN7android3net16DnsProxyListener15ResNSendCommand10runCommandEP12SocketClientiPPc"};
    const Command handlers[] = {command0, command1, command2, command3};
    void *targets[4]{};
    const unsigned count = sdk < 29 ? 3 : 4;
    for (unsigned i = 0; i < count; ++i) {
        targets[i] = api->symbolLookup(symbols, names[i], false, nullptr);
        if (!targets[i]) {
            api->freeSymbolResolver(symbols);
            return false;
        }
    }
    const char *legacy[] = {"_ZN7android3net12_GLOBAL__N_110threadMainINS0_"
                            "16DnsProxyListener18GetAddrInfoHandlerEEEPvS5_",
                            "_ZN7android3net12_GLOBAL__N_110threadMainINS0_"
                            "16DnsProxyListener20GetHostByNameHandlerEEEPvS5_",
                            "_ZN7android3net12_GLOBAL__N_110threadMainINS0_"
                            "16DnsProxyListener20GetHostByAddrHandlerEEEPvS5_"};
    if (sdk == 27) {
        // API27 can strip its launch-wrapper symbols. Its named
        // runCommand scopes synchronously create their DNS workers via this
        // object's pthread_create PLT. Conservatively retain every thread
        // created inside an observed query command, including its destructor.
        track_command_threads = true;
    } else if (sdk < 28) {
        for (const char *name : legacy) {
            void *routine = api->symbolLookup(symbols, name, false, nullptr);
            if (!routine) {
                api->freeSymbolResolver(symbols);
                return false;
            }
            allowed_routines[routine_count++] = reinterpret_cast<Routine>(routine);
        }
    } else if (sdk >= 28 && sdk <= 30) {
        const char *pie[] = {
            "_ZN7android3net12runAndDeleteINS0_16DnsProxyListener18GetAddrInfoHandlerEEEPvS4_",
            "_ZN7android3net12runAndDeleteINS0_16DnsProxyListener20GetHostByNameHandlerEEEPvS4_",
            "_ZN7android3net12runAndDeleteINS0_16DnsProxyListener20GetHostByAddrHandlerEEEPvS4_"};
        const char *q[] = {"_ZN7android9netdutils12runAndDeleteINS_"
                           "3net16DnsProxyListener18GetAddrInfoHandlerEEEPvS5_",
                           "_ZN7android9netdutils12runAndDeleteINS_"
                           "3net16DnsProxyListener20GetHostByNameHandlerEEEPvS5_",
                           "_ZN7android9netdutils12runAndDeleteINS_"
                           "3net16DnsProxyListener20GetHostByAddrHandlerEEEPvS5_",
                           "_ZN7android9netdutils12runAndDeleteINS_"
                           "3net16DnsProxyListener15ResNSendHandlerEEEPvS5_"};
        for (unsigned i = 0; i < count; ++i) {
            void *routine = api->symbolLookup(symbols, sdk == 28 ? pie[i] : q[i], false, nullptr);
            if (!routine) {
                api->freeSymbolResolver(symbols);
                return false;
            }
            allowed_routines[routine_count++] = reinterpret_cast<Routine>(routine);
            if (sdk == 30) {
                char cfi[160];
                std::snprintf(cfi, sizeof(cfi), "%s.cfi", q[i]);
                routine = api->symbolLookup(symbols, cfi, false, nullptr);
                if (routine)
                    allowed_routines[routine_count++] = reinterpret_cast<Routine>(routine);
            }
        }
    } else {
        void *routine = api->symbolLookup(
            symbols,
            "_ZN7android9netdutils12runAndDeleteINS_3net16DnsProxyListener7HandlerEEEPvS5_",
            false,
            nullptr);
        if (!routine) {
            api->freeSymbolResolver(symbols);
            return false;
        }
        allowed_routines[routine_count++] = reinterpret_cast<Routine>(routine);
        routine = api->symbolLookup(
            symbols,
            "_ZN7android9netdutils12runAndDeleteINS_3net16DnsProxyListener7HandlerEEEPvS5_.cfi",
            false,
            nullptr);
        if (routine)
            allowed_routines[routine_count++] = reinterpret_cast<Routine>(routine);
    }
    void *base = api->getBaseAddress(symbols);
    if (api->pltHook(base,
                     "pthread_create",
                     reinterpret_cast<void *>(create_thread),
                     reinterpret_cast<void **>(&original_create)) != ZN_SUCCESS) {
        api->freeSymbolResolver(symbols);
        return false;
    }
    unsigned hooked = 0;
    for (; hooked < count; ++hooked) {
        if (api->inlineHook(targets[hooked],
                            reinterpret_cast<void *>(handlers[hooked]),
                            reinterpret_cast<void **>(&commands[hooked])) != ZN_SUCCESS)
            break;
    }
    if (hooked != count) {
        for (unsigned i = 0; i < hooked; ++i)
            api->inlineUnhook(targets[i]);
        api->pltHook(base, "pthread_create", reinterpret_cast<void *>(original_create), nullptr);
        api->freeSymbolResolver(symbols);
        return false;
    }
    api->freeSymbolResolver(symbols);
    ready.store(true);
    return true;
}
