// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0

#include "peer_auth.h"
#include "../common/authority.h"
#include <cerrno>
#include <cstddef>
#include <cstring>
#include <poll.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

bool ae_authorize_root(int connection) {
    ucred caller{};
    socklen_t size = sizeof(caller);
    return !getsockopt(connection, SOL_SOCKET, SO_PEERCRED, &caller, &size) &&
           size == sizeof(caller) && caller.uid == 0 && caller.pid > 1;
}

bool ae_authorize_control_owner(int connection) {
    ucred caller{};
    socklen_t size = sizeof(caller);
    if (getsockopt(connection, SOL_SOCKET, SO_PEERCRED, &caller, &size) || size != sizeof(caller) ||
        caller.uid != 0 || caller.pid <= 1)
        return false;
    const int control = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    if (control < 0)
        return false;
    sockaddr_un address{};
    address.sun_family = AF_UNIX;
    constexpr char name[] = "asteriskd.control";
    std::memcpy(address.sun_path + 1, name, sizeof(name) - 1);
    int result = connect(control,
                         reinterpret_cast<sockaddr *>(&address),
                         offsetof(sockaddr_un, sun_path) + sizeof(name));
    if (result && errno == EINPROGRESS) {
        pollfd event{control, POLLOUT, 0};
        result = poll(&event, 1, 2000) > 0 ? 0 : -1;
        if (!result) {
            int error = 0;
            size = sizeof(error);
            if (getsockopt(control, SOL_SOCKET, SO_ERROR, &error, &size) || error)
                result = -1;
        }
    }
    ucred authority{};
    size = sizeof(authority);
    if (!result && (getsockopt(control, SOL_SOCKET, SO_PEERCRED, &authority, &size) ||
                    size != sizeof(authority)))
        result = -1;
    close(control);
    if (result)
        return false;
    const AePeerIdentity caller_identity{caller.uid, static_cast<uint32_t>(caller.pid)};
    const AePeerIdentity authority_identity{authority.uid, static_cast<uint32_t>(authority.pid)};
    // Connecting is enough to inspect the kernel listener identity. Do not send
    // a synchronous control request that could deadlock the daemon's handshake.
    return ae_peer_is_authority(&caller_identity, &authority_identity) != 0;
}
