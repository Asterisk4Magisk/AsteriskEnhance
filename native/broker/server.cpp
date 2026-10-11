// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0

#include "server.h"
#include "peer_auth.h"
#include "io.h"
#include <cerrno>
#include <cstdlib>
#include <array>
#include <cstring>
#include <poll.h>
#include <pthread.h>
#include <sys/socket.h>
#include <unistd.h>
namespace {
pthread_mutex_t single_netd = PTHREAD_MUTEX_INITIALIZER;
}
void ae_broker_serve(int channel) {
    if (pthread_mutex_trylock(&single_netd))
        return;
    // The private netd channel sends a bounded immutable loaded-image snapshot.
    AeWireHeader metadata{};
    uint8_t metadata_header[AE_WIRE_HEADER_SIZE];
    const uint64_t startup_deadline = ae_now_ms() + AE_CONTROL_TIMEOUT_MILLISECONDS;
    if (!ae_io(channel, metadata_header, sizeof(metadata_header), false, startup_deadline) ||
        !ae_wire_decode(metadata_header, sizeof(metadata_header), &metadata) ||
        metadata.opcode != AE_INFO_REPLY) {
        pthread_mutex_unlock(&single_netd);
        return;
    }
    std::vector<uint8_t> information(metadata.body_length);
    if (!ae_io(channel, information.data(), information.size(), false, startup_deadline)) {
        pthread_mutex_unlock(&single_netd);
        return;
    }
    struct Pending {
        int fd = -1;
        uint64_t deadline = 0;
        size_t size = 0;
        uint8_t header[AE_WIRE_HEADER_SIZE]{};
    };
    std::array<Pending, 8> pending{};
    const int listener = ae_abstract_listener("asterisk.enhance.dns");
    int client = -1;
    bool hello_pending = false;
    AeWireHeader hello{};
    uint64_t connection = 0;
    arc4random_buf(&connection, sizeof(connection));
    if (connection == UINT64_MAX)
        --connection;
    if (listener >= 0)
        for (;;) {
            std::array<pollfd, 11> events{};
            events[0] = {channel, POLLIN, 0};
            events[1] = {listener, POLLIN, 0};
            events[2] = {client, POLLIN, 0};
            for (size_t i = 0; i < pending.size(); ++i)
                events[3 + i] = {pending[i].fd, POLLIN, 0};
            int timeout = hello_pending ? 0 : -1;
            const uint64_t now = ae_now_ms();
            for (const auto &slot : pending) {
                if (slot.fd < 0)
                    continue;
                const int remaining =
                    slot.deadline > now ? static_cast<int>(slot.deadline - now) : 0;
                if (timeout < 0 || remaining < timeout)
                    timeout = remaining;
            }
            const int count = poll(events.data(), events.size(), timeout);
            if (count < 0 && errno == EINTR)
                continue;
            if (count < 0)
                break;
            if (events[0].revents) {
                AeWireHeader notification{};
                std::vector<uint8_t> payload;
                const uint64_t deadline = ae_now_ms() + AE_CONTROL_TIMEOUT_MILLISECONDS;
                if (!ae_read_frame(channel, &notification, &payload, deadline) ||
                    notification.opcode != AE_NETWORK_CHANGED)
                    break;
                if (client >= 0 && !ae_write_frame(client, notification, payload, deadline))
                    break;
            }
            if (events[1].revents & POLLIN) {
                const int incoming =
                    accept4(listener, nullptr, nullptr, SOCK_CLOEXEC | SOCK_NONBLOCK);
                if (incoming >= 0) {
                    bool queued = false;
                    if (ae_authorize_root(incoming))
                        for (auto &slot : pending)
                            if (slot.fd < 0) {
                                slot = {incoming, ae_now_ms() + 500};
                                queued = true;
                                break;
                            }
                    if (!queued)
                        close(incoming);
                }
            }
            for (size_t i = 0; i < pending.size(); ++i) {
                auto &slot = pending[i];
                if (slot.fd < 0)
                    continue;
                bool finished = ae_now_ms() >= slot.deadline;
                if (!finished && events[3 + i].revents) {
                    // Read only the fixed discriminant before choosing authorization.
                    const size_t target = slot.size < 8 ? 8 : sizeof(slot.header);
                    const ssize_t n =
                        recv(slot.fd, slot.header + slot.size, target - slot.size, MSG_DONTWAIT);
                    if (n > 0)
                        slot.size += static_cast<size_t>(n);
                    if (n > 0 && slot.size == 8) {
                        const uint8_t info_prefix[] = {'A', 'E', 'N', '1', 1, 0, AE_INFO, 0};
                        const uint8_t hello_prefix[] = {'A', 'E', 'N', '1', 1, 0, AE_HELLO, 0};
                        if (std::memcmp(slot.header, info_prefix, 8) &&
                            (std::memcmp(slot.header, hello_prefix, 8) || client >= 0 ||
                             !ae_authorize_control_owner(slot.fd)))
                            finished = true;
                    }
                    if (slot.size == sizeof(slot.header)) {
                        AeWireHeader first{};
                        finished = true;
                        if (ae_wire_decode(slot.header, sizeof(slot.header), &first) &&
                            ae_authorize_root(slot.fd)) {
                            if (first.opcode == AE_INFO) {
                                // One tiny nonblocking write: a slow reader never stalls control
                                // requests.
                                uint8_t reply[AE_WIRE_HEADER_SIZE + 512];
                                AeWireHeader header{AE_INFO_REPLY,
                                                    static_cast<uint32_t>(information.size()),
                                                    first.request_id,
                                                    0,
                                                    0,
                                                    0};
                                ae_wire_encode(&header, reply, sizeof(reply));
                                std::memcpy(reply + AE_WIRE_HEADER_SIZE,
                                            information.data(),
                                            information.size());
                                send(slot.fd,
                                     reply,
                                     AE_WIRE_HEADER_SIZE + information.size(),
                                     MSG_DONTWAIT | MSG_NOSIGNAL);
                            } else if (first.opcode == AE_HELLO && client < 0 &&
                                       connection != UINT64_MAX &&
                                       ae_authorize_control_owner(slot.fd)) {
                                client = slot.fd;
                                hello = first;
                                hello_pending = true;
                                slot.fd = -1;
                                ++connection;
                            }
                        }
                    } else if (n <= 0 && (n == 0 || (errno != EAGAIN && errno != EWOULDBLOCK &&
                                                     errno != EINTR))) {
                        finished = true;
                    } else if (events[3 + i].revents & (POLLHUP | POLLERR)) {
                        finished = true;
                    }
                }
                if (finished && slot.fd >= 0) {
                    close(slot.fd);
                    slot.fd = -1;
                }
            }
            if (client < 0 || (!events[2].revents && !hello_pending))
                continue;
            AeWireHeader request{}, reply{};
            std::vector<uint8_t> body, response;
            uint64_t deadline = ae_now_ms() + AE_CONTROL_TIMEOUT_MILLISECONDS;
            bool disconnect = false;
            const bool first = hello_pending;
            hello_pending = false;
            if (first)
                request = hello;
            bool valid = ae_authorize_control_owner(client) &&
                         (first || ae_read_frame(client, &request, &body, deadline)) &&
                         request.opcode >= AE_HELLO && request.opcode <= AE_RELEASE &&
                         ae_authorize_control_owner(client);
            if (valid) {
                valid = ae_envelope(channel, &connection, &disconnect, true, &deadline) &&
                        ae_write_frame(channel, request, body, deadline);
                while (valid) {
                    valid = ae_read_frame(channel, &reply, &response, deadline);
                    if (!valid || reply.opcode != AE_NETWORK_CHANGED)
                        break;
                    valid = ae_write_frame(client, reply, response, deadline);
                }
                valid = valid && reply.request_id == request.request_id &&
                        reply.instance == request.instance && reply.cycle == request.cycle &&
                        reply.generation == request.generation &&
                        (reply.opcode == AE_ACK || reply.opcode == AE_ERROR ||
                         reply.opcode == AE_CAPABILITIES);
                if (!valid)
                    break; // Discard late ACKs by closing the private channel.
                valid = ae_write_frame(client, reply, response, deadline);
            }
            if (!valid) {
                close(client);
                client = -1;
                disconnect = true;
                uint64_t cleanup_deadline = ae_now_ms() + AE_CONTROL_TIMEOUT_MILLISECONDS;
                if (!ae_envelope(channel, &connection, &disconnect, true, &cleanup_deadline))
                    break;
            }
        }
    for (auto &slot : pending)
        if (slot.fd >= 0)
            close(slot.fd);
    if (client >= 0)
        close(client);
    if (listener >= 0)
        close(listener);
    pthread_mutex_unlock(&single_netd);
}
