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
// First-frame budget for a newly accepted connection.
constexpr uint64_t kPendingMilliseconds = 500;
struct Pending {
    int fd = -1;
    uint64_t deadline = 0;
    size_t size = 0;
    uint8_t header[AE_WIRE_HEADER_SIZE]{};
};
void close_pending(Pending &slot) {
    if (slot.fd >= 0)
        close(slot.fd);
    slot = Pending{};
}
} // namespace
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
    std::array<Pending, 8> pending{};
    const int listener = ae_abstract_listener("asterisk.enhance.dns");
    int client = -1;
    uint64_t connection = 0;
    arc4random_buf(&connection, sizeof(connection));
    if (connection == UINT64_MAX)
        --connection;
    // At most one forwarded request is outstanding; netd serves them serially.
    // While it is outstanding the broker keeps answering INFO and accepting
    // connections instead of blocking on the netd reply.
    bool inflight = false;
    AeWireHeader request{};
    uint64_t inflight_deadline = 0;
    // The next client request is assembled without blocking, within its own
    // framing deadline, so a stalled partial frame never delays other work.
    uint8_t client_header[AE_WIRE_HEADER_SIZE];
    size_t client_size = 0;
    AeWireHeader client_request{};
    std::vector<uint8_t> client_body;
    uint64_t client_deadline = 0;
    // Set when the client slot frees up, so a waiting HELLO is served at once.
    bool revisit = false;
    // Drops only the control client. The private channel stays up; netd
    // withdraws this connection's policy when it reads the disconnect.
    auto drop_client = [&]() {
        if (client >= 0)
            close(client);
        client = -1;
        client_size = 0;
        client_body.clear();
        revisit = true;
        bool disconnect = true;
        uint64_t deadline = ae_now_ms() + AE_CONTROL_TIMEOUT_MILLISECONDS;
        return ae_envelope(channel, &connection, &disconnect, true, &deadline);
    };
    auto forward = [&](const AeWireHeader &header, std::vector<uint8_t> &body) {
        bool disconnect = false;
        uint64_t deadline = ae_now_ms() + AE_CONTROL_TIMEOUT_MILLISECONDS;
        if (!ae_envelope(channel, &connection, &disconnect, true, &deadline) ||
            !ae_write_frame(channel, header, body, deadline))
            return false;
        request = header;
        inflight_deadline = deadline;
        inflight = true;
        return true;
    };
    if (listener >= 0)
        for (;;) {
            std::array<pollfd, 11> events{};
            events[0] = {channel, POLLIN, 0};
            events[1] = {listener, POLLIN, 0};
            events[2] = {inflight ? -1 : client, POLLIN, 0};
            for (size_t i = 0; i < pending.size(); ++i)
                events[3 + i] = {pending[i].fd, POLLIN, 0};
            uint64_t wake = inflight ? inflight_deadline : UINT64_MAX;
            if (client >= 0 && client_size && client_deadline < wake)
                wake = client_deadline;
            for (const auto &slot : pending)
                if (slot.fd >= 0 && slot.deadline < wake)
                    wake = slot.deadline;
            const uint64_t now = ae_now_ms();
            int timeout = -1;
            if (wake != UINT64_MAX)
                timeout = wake > now ? static_cast<int>(wake - now) : 0;
            if (revisit)
                timeout = 0;
            revisit = false;
            const int count = poll(events.data(), events.size(), timeout);
            if (count < 0 && errno == EINTR)
                continue;
            if (count < 0)
                break;
            if (events[0].revents) {
                AeWireHeader frame{};
                std::vector<uint8_t> payload;
                const uint64_t deadline = ae_now_ms() + AE_CONTROL_TIMEOUT_MILLISECONDS;
                if (!ae_read_frame(channel, &frame, &payload, deadline))
                    break;
                if (frame.opcode == AE_NETWORK_CHANGED) {
                    if (client >= 0 && !ae_write_frame(client, frame, payload, deadline) &&
                        !drop_client())
                        break;
                } else {
                    // Any reply must answer the outstanding request exactly.
                    if (!inflight || frame.request_id != request.request_id ||
                        frame.instance != request.instance || frame.cycle != request.cycle ||
                        frame.generation != request.generation ||
                        (frame.opcode != AE_ACK && frame.opcode != AE_ERROR &&
                         frame.opcode != AE_CAPABILITIES))
                        break;
                    inflight = false;
                    revisit = true;
                    // A client dropped while waiting already sent its disconnect.
                    if (client >= 0 && !ae_write_frame(client, frame, payload, deadline) &&
                        !drop_client())
                        break;
                }
            }
            // Discard late replies by closing the private channel.
            if (inflight && ae_now_ms() >= inflight_deadline)
                break;
            if (events[1].revents & POLLIN) {
                const int incoming =
                    accept4(listener, nullptr, nullptr, SOCK_CLOEXEC | SOCK_NONBLOCK);
                if (incoming >= 0) {
                    bool queued = false;
                    if (ae_authorize_root(incoming))
                        for (auto &slot : pending)
                            if (slot.fd < 0) {
                                slot = Pending{};
                                slot.fd = incoming;
                                slot.deadline = ae_now_ms() + kPendingMilliseconds;
                                queued = true;
                                break;
                            }
                    if (!queued)
                        close(incoming);
                }
            }
            bool start_hello = false;
            AeWireHeader hello{};
            for (size_t i = 0; i < pending.size(); ++i) {
                auto &slot = pending[i];
                if (slot.fd < 0)
                    continue;
                bool finished = false;
                // Consume available bytes before judging the deadline, so a
                // complete header is still served after a slow iteration.
                if (events[3 + i].revents) {
                    // A complete header expects no further bytes before its reply.
                    if (slot.size == sizeof(slot.header)) {
                        finished = true;
                    } else {
                        // Read only the fixed discriminant before choosing authorization.
                        const size_t target = slot.size < 8 ? 8 : sizeof(slot.header);
                        const ssize_t n = recv(
                            slot.fd, slot.header + slot.size, target - slot.size, MSG_DONTWAIT);
                        if (n > 0) {
                            slot.size += static_cast<size_t>(n);
                        } else if (n == 0 ||
                                   (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)) {
                            finished = true;
                        } else if (events[3 + i].revents & (POLLHUP | POLLERR)) {
                            finished = true;
                        }
                        if (n > 0 && slot.size == 8) {
                            const uint8_t info_prefix[] = {'A', 'E', 'N', '1', 1, 0, AE_INFO, 0};
                            const uint8_t hello_prefix[] = {
                                'A', 'E', 'N', '1', 1, 0, AE_HELLO, 0};
                            if (std::memcmp(slot.header, info_prefix, 8) &&
                                std::memcmp(slot.header, hello_prefix, 8))
                                finished = true;
                        }
                    }
                }
                if (!finished && slot.size == sizeof(slot.header)) {
                    AeWireHeader first{};
                    if (!ae_wire_decode(slot.header, sizeof(slot.header), &first)) {
                        finished = true;
                    } else if (first.opcode == AE_INFO) {
                        // One tiny nonblocking write: a slow reader never stalls control
                        // requests.
                        uint8_t reply[AE_WIRE_HEADER_SIZE + 512];
                        AeWireHeader header{AE_INFO_REPLY,
                                            static_cast<uint32_t>(information.size()),
                                            first.request_id,
                                            0,
                                            0,
                                            0};
                        if (ae_wire_encode(&header, reply, sizeof(reply))) {
                            std::memcpy(
                                reply + AE_WIRE_HEADER_SIZE, information.data(), information.size());
                            send(slot.fd,
                                 reply,
                                 AE_WIRE_HEADER_SIZE + information.size(),
                                 MSG_DONTWAIT | MSG_NOSIGNAL);
                        }
                        finished = true;
                    } else if (first.opcode != AE_HELLO || start_hello ||
                               connection == UINT64_MAX) {
                        finished = true;
                    } else if (client < 0 && !inflight) {
                        // A current client or a reply still owed to a dropped one
                        // delays HELLO within its first-header deadline: a
                        // restarting supervisor's HELLO may arrive before the
                        // broker has observed the old connection closing.
                        if (ae_authorize_control_owner(slot.fd)) {
                            client = slot.fd;
                            hello = first;
                            start_hello = true;
                            slot.fd = -1;
                            ++connection;
                        }
                        finished = true;
                    }
                }
                if (!finished && slot.fd >= 0 && ae_now_ms() >= slot.deadline)
                    finished = true;
                if (finished)
                    close_pending(slot);
            }
            if (start_hello) {
                // HELLO was authorized against the listener owner when it was read.
                std::vector<uint8_t> empty;
                if (!forward(hello, empty))
                    break;
                continue;
            }
            if (client < 0 || inflight)
                continue;
            bool failed = false;
            if (events[2].revents) {
                ssize_t n;
                if (client_size < AE_WIRE_HEADER_SIZE)
                    n = recv(client,
                             client_header + client_size,
                             AE_WIRE_HEADER_SIZE - client_size,
                             MSG_DONTWAIT);
                else
                    n = recv(client,
                             client_body.data() + (client_size - AE_WIRE_HEADER_SIZE),
                             client_request.body_length - (client_size - AE_WIRE_HEADER_SIZE),
                             MSG_DONTWAIT);
                if (n > 0) {
                    if (!client_size)
                        client_deadline = ae_now_ms() + AE_CONTROL_TIMEOUT_MILLISECONDS;
                    client_size += static_cast<size_t>(n);
                    if (client_size == AE_WIRE_HEADER_SIZE) {
                        if (!ae_wire_decode(client_header, sizeof(client_header), &client_request) ||
                            client_request.opcode < AE_HELLO || client_request.opcode > AE_RELEASE)
                            failed = true;
                        else
                            client_body.resize(client_request.body_length);
                    }
                } else if (n == 0 || (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)) {
                    failed = true;
                }
            }
            if (!failed && client_size &&
                client_size == AE_WIRE_HEADER_SIZE + client_body.size() &&
                client_size >= AE_WIRE_HEADER_SIZE) {
                client_size = 0;
                // SO_PEERCRED is fixed at connect time; confirm once per complete
                // request that this peer still owns the control listener.
                if (!ae_authorize_control_owner(client))
                    failed = true;
                else if (!forward(client_request, client_body))
                    break;
                else
                    client_body.clear();
            } else if (!failed && client_size && ae_now_ms() >= client_deadline) {
                failed = true; // A partial request outlived its framing deadline.
            }
            if (failed && !drop_client())
                break;
        }
    for (auto &slot : pending)
        close_pending(slot);
    if (client >= 0)
        close(client);
    if (listener >= 0)
        close(listener);
    pthread_mutex_unlock(&single_netd);
}
