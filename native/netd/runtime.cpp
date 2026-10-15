// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0

#include "runtime.h"
#include "resolver_backend.h"
#include "../common/session.h"
#include "../common/store.h"
#include "../broker/io.h"
#include <cerrno>
#include <cstdio>
#include "ae_build_identity.h"
#include <cstdlib>
#include <poll.h>
#include <pthread.h>
#include <atomic>
#include <sys/eventfd.h>
#include <unistd.h>
namespace {
pthread_mutex_t writer = PTHREAD_MUTEX_INITIALIZER;
std::atomic<int> network_event{-1}, drain_event{-1};
void *actor = nullptr;
void *session = nullptr;
std::vector<uint8_t> runtime_info;
} // namespace
void ae_runtime_lock() {
    pthread_mutex_lock(&writer);
}
void ae_runtime_unlock() {
    pthread_mutex_unlock(&writer);
}
bool ae_runtime_init(uint64_t instance, uint32_t api, uint32_t modes, uint32_t flags) {
    AeRuntimeGuard guard;
    if (session)
        return true;
    const int event = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
    if (event < 0)
        return false;
    const int drained = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
    if (drained < 0) {
        close(event);
        return false;
    }
    actor = std::calloc(1, ae_actor_size());
    session = std::calloc(1, ae_session_size());
    const auto backend = ae_backend_callbacks();
    if (!actor || !session ||
        !ae_actor_init(actor, ae_store_global(), instance, arc4random(), modes, &backend) ||
        !ae_session_init(session, actor, instance, api, modes, flags)) {
        std::free(actor);
        std::free(session);
        close(event);
        close(drained);
        actor = nullptr;
        session = nullptr;
        return false;
    }
    char text[512];
    const int length = std::snprintf(text,
                                     sizeof(text),
                                     "AE_INFO "
                                     "1\nversionCode=%s\nversion=%s\nbuildId=%s\nnetd=%llu\napi=%"
                                     "u\nmodes=%u\nflags=%u\nprotocol=7\n",
                                     AE_MODULE_VERSION_CODE,
                                     AE_MODULE_VERSION,
                                     AE_MODULE_BUILD_ID,
                                     static_cast<unsigned long long>(instance),
                                     api,
                                     modes,
                                     flags);
    if (length <= 0 || static_cast<size_t>(length) >= sizeof(text))
        return false;
    runtime_info.assign(text, text + length);
    network_event.store(event);
    drain_event.store(drained);
    return true;
}
namespace {
void signal(int event) {
    if (event >= 0) {
        const uint64_t one = 1;
        ssize_t result;
        do {
            result = write(event, &one, sizeof(one));
        } while (result < 0 && errno == EINTR);
    }
}
void consume(int event) {
    uint64_t changes;
    ssize_t result;
    do {
        result = read(event, &changes, sizeof(changes));
    } while (result < 0 && errno == EINTR);
}
} // namespace
void ae_runtime_network_changed() {
    // Called by resolver hooks. Never take the writer lock or call Binder here.
    signal(network_event.load());
}
void ae_runtime_drained() {
    // Called by resolver threads; the serving thread reaps under the writer lock.
    signal(drain_event.load());
}
void ae_runtime_reap() {
    AeRuntimeGuard guard;
    if (actor)
        ae_actor_reap(actor);
}
void ae_runtime_serve(int channel) {
    if (!session)
        return;
    // Metadata originates in the netd-loaded image, never the companion's disk image.
    AeWireHeader info{AE_INFO_REPLY, static_cast<uint32_t>(runtime_info.size()), 1, 0, 0, 0};
    if (!ae_write_frame(channel, info, runtime_info, ae_now_ms() + AE_CONTROL_TIMEOUT_MILLISECONDS))
        return;
    uint64_t current = 0;
    for (;;) {
        ae_runtime_reap();
        pollfd events[] = {{channel, POLLIN, 0},
                           {network_event.load(), POLLIN, 0},
                           {drain_event.load(), POLLIN, 0}};
        int timeout;
        {
            AeRuntimeGuard guard;
            timeout = ae_actor_poll_timeout(actor);
        }
        const int ready = poll(events, 3, timeout);
        if (ready < 0 && errno == EINTR)
            continue;
        if (ready < 0)
            break;
        if (!ready)
            continue;
        bool notify = false;
        if (events[2].revents & POLLIN) {
            consume(events[2].fd);
            // Finish automatic cleanup now; a waiting client retries RELEASE.
            ae_runtime_reap();
            notify = true;
        }
        if (events[1].revents & POLLIN) {
            consume(events[1].fd);
            notify = true;
        }
        if (notify) {
            if (current) {
                AeWireHeader changed{AE_NETWORK_CHANGED, 0, 1, 0, 0, 0};
                std::vector<uint8_t> empty;
                if (!ae_write_frame(
                        channel, changed, empty, ae_now_ms() + AE_CONTROL_TIMEOUT_MILLISECONDS))
                    break;
            }
        }
        if (!events[0].revents)
            continue;
        uint64_t deadline = ae_now_ms() + AE_CONTROL_TIMEOUT_MILLISECONDS;
        uint64_t connection = 0;
        bool disconnect = false;
        if (!ae_envelope(channel, &connection, &disconnect, false, &deadline))
            break;
        if (disconnect) {
            AeRuntimeGuard guard;
            if (current == connection) {
                ae_session_close(session);
                current = 0;
            }
            continue;
        }
        AeWireHeader header{};
        std::vector<uint8_t> body;
        if (!ae_read_frame(channel, &header, &body, deadline))
            break;
        uint8_t response[AE_RESPONSE_MAX_SIZE];
        size_t length = 0;
        {
            AeRuntimeGuard guard;
            if (ae_now_ms() >= deadline)
                break;
            if (current != connection) {
                ae_session_open(session, connection);
                current = connection;
            }
            length = ae_session_handle_until(session,
                                             &header,
                                             body.data(),
                                             body.size(),
                                             ae_now_ms(),
                                             deadline,
                                             response,
                                             sizeof(response));
        }
        if (!length || !ae_io(channel, response, length, true, deadline))
            break;
    }
    AeRuntimeGuard guard;
    ae_session_close(session);
    ae_actor_reap(actor);
}
