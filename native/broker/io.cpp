// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0

#include "io.h"
#include <cerrno>
#include <climits>
#include <cstring>
#include <poll.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>
uint64_t ae_now_ms() {
    timespec now{};
    if (clock_gettime(CLOCK_BOOTTIME, &now))
        return UINT64_MAX;
    return static_cast<uint64_t>(now.tv_sec) * 1000U +
           static_cast<uint64_t>(now.tv_nsec) / 1000000U;
}
bool ae_io(int fd, void *data, size_t length, bool sending, uint64_t deadline) {
    auto *bytes = static_cast<uint8_t *>(data);
    while (length) {
        const uint64_t now = ae_now_ms();
        if (now >= deadline)
            return false;
        const uint64_t remaining = deadline - now;
        pollfd event{fd, static_cast<short>(sending ? POLLOUT : POLLIN), 0};
        const int ready =
            poll(&event, 1, remaining > INT_MAX ? INT_MAX : static_cast<int>(remaining));
        if (ready < 0 && errno == EINTR)
            continue;
        if (ready <= 0 || ae_now_ms() >= deadline)
            return false;
        const ssize_t n = sending ? send(fd, bytes, length, MSG_NOSIGNAL | MSG_DONTWAIT)
                                  : recv(fd, bytes, length, MSG_DONTWAIT);
        if (n < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK))
            continue;
        if (n <= 0)
            return false;
        bytes += n;
        length -= static_cast<size_t>(n);
    }
    return ae_now_ms() < deadline;
}
bool ae_read_frame(int fd, AeWireHeader *header, std::vector<uint8_t> *body, uint64_t deadline) {
    uint8_t bytes[AE_WIRE_HEADER_SIZE];
    if (!header || !body || !ae_io(fd, bytes, sizeof(bytes), false, deadline) ||
        !ae_wire_decode(bytes, sizeof(bytes), header))
        return false;
    body->resize(header->body_length);
    return ae_io(fd, body->data(), body->size(), false, deadline);
}
bool ae_write_frame(int fd,
                    const AeWireHeader &header,
                    std::vector<uint8_t> &body,
                    uint64_t deadline) {
    uint8_t bytes[AE_WIRE_HEADER_SIZE];
    return header.body_length == body.size() && ae_wire_encode(&header, bytes, sizeof(bytes)) &&
           ae_io(fd, bytes, sizeof(bytes), true, deadline) &&
           ae_io(fd, body.data(), body.size(), true, deadline);
}
int ae_abstract_listener(const char *name) {
    const size_t length = std::strlen(name);
    sockaddr_un address{};
    address.sun_family = AF_UNIX;
    if (length + 1 > sizeof(address.sun_path))
        return -1;
    const int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    if (fd < 0)
        return -1;
    std::memcpy(address.sun_path + 1, name, length);
    if (bind(fd,
             reinterpret_cast<sockaddr *>(&address),
             offsetof(sockaddr_un, sun_path) + length + 1) ||
        listen(fd, 4)) {
        close(fd);
        return -1;
    }
    return fd;
}
bool ae_envelope(int fd, uint64_t *connection, bool *disconnect, bool sending, uint64_t *deadline) {
    uint8_t bytes[24] = {'A', 'E', 'I', 1};
    if (sending) {
        bytes[4] = *disconnect ? 2 : 1;
        for (unsigned i = 0; i < 8; ++i)
            bytes[8 + i] = static_cast<uint8_t>(*connection >> (8 * i));
        for (unsigned i = 0; i < 8; ++i)
            bytes[16 + i] = static_cast<uint8_t>(*deadline >> (8 * i));
    }
    if (!ae_io(fd, bytes, sizeof(bytes), sending, *deadline))
        return false;
    if (sending)
        return true;
    if (bytes[0] != 'A' || bytes[1] != 'E' || bytes[2] != 'I' || bytes[3] != 1 ||
        (bytes[4] != 1 && bytes[4] != 2) || bytes[5] || bytes[6] || bytes[7])
        return false;
    *disconnect = bytes[4] == 2;
    *connection = 0;
    for (unsigned i = 0; i < 8; ++i)
        *connection |= static_cast<uint64_t>(bytes[8 + i]) << (8 * i);
    uint64_t remote_deadline = 0;
    for (unsigned i = 0; i < 8; ++i)
        remote_deadline |= static_cast<uint64_t>(bytes[16 + i]) << (8 * i);
    if (remote_deadline < *deadline)
        *deadline = remote_deadline;
    return *connection != 0 && ae_now_ms() < *deadline;
}
