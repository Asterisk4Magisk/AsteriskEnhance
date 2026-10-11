// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0

#include <android/log.h>
#include <android/dlext.h>
#include <atomic>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dlfcn.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/system_properties.h>
#include <unistd.h>
#include <time.h>
#include <type_traits>
#include "zygisk_next_api.h"
#include "resolver_bridge.h"
#include "../common/store.h"
#include "query_lifetime.h"
#include "resolver_backend.h"
#include "runtime.h"
#include "../broker/server.h"
#include "../common/session.h"

namespace {
constexpr const char *kTag = "AsteriskEnhance";
struct NetContext26 {
    uint32_t app_netid, app_mark, dns_netid, dns_mark, uid;
};
struct NetContext28 {
    NetContext26 prefix;
    uint32_t flags;
    void *qhook;
};
static_assert(sizeof(NetContext28) == 24 + sizeof(void *));
static_assert(sizeof(NetContext26) == 20);
std::atomic<bool> controller_constructed{false};
using ContextFunction = void (*)(const void *, uint32_t, uint32_t, void *);
ContextFunction original_context = nullptr;
std::atomic<const void *> network_controller{nullptr};
#if defined(__arm__)
// The ARM32 C++ ABI returns this from C1/C2 constructors.
using ControllerResult = void *;
#else
using ControllerResult = void;
#endif
using ControllerConstructor = ControllerResult (*)(void *);
ControllerConstructor original_constructor1 = nullptr, original_constructor2 = nullptr;

template <typename Result>
Result construct_controller(Result (*original)(void *), void *controller) {
    if constexpr (std::is_void<Result>::value) {
        original(controller);
        network_controller.store(controller, std::memory_order_release);
        controller_constructed.store(true);
    } else {
        Result result = original(controller);
        network_controller.store(controller, std::memory_order_release);
        controller_constructed.store(true);
        return result;
    }
}
ControllerResult construct_controller1(void *controller) {
    return construct_controller(original_constructor1, controller);
}
ControllerResult construct_controller2(void *controller) {
    return construct_controller(original_constructor2, controller);
}
using DnsNetworkFunction = uint32_t (*)(const void *, uint32_t *, uint32_t);
DnsNetworkFunction original_dns_network = nullptr;
thread_local bool inside_original_context = false;
ZygiskNextAPI runtime_api{};
void *module_handle = nullptr;
std::atomic<bool> hook_installed{false};
int platform_api = 0;
#if defined(__LP64__)
const char *resolver_path = "/apex/com.android.resolv/lib64/libnetd_resolv.so";
#else
const char *resolver_path = "/apex/com.android.resolv/lib/libnetd_resolv.so";
#endif
uint64_t netd_instance = 0;
void *modern_bridge = nullptr;

void decorate_context(AeContext *context) {
    if (!context || !ae_query_in_command())
        return;
    if (ae_store_has_active(ae_store_global())) {
        timespec now{};
        if (!clock_gettime(CLOCK_BOOTTIME, &now)) {
            const uint64_t milliseconds = static_cast<uint64_t>(now.tv_sec) * 1000U +
                                          static_cast<uint64_t>(now.tv_nsec) / 1000000U;
            ae_store_apply_observed(
                ae_store_global(), netd_instance, milliseconds, context, ae_query_observe, nullptr);
        }
    }
}

// Production remains inactive until an authenticated policy is published.
void get_context(const void *controller, uint32_t netid, uint32_t uid, void *result) {
    network_controller.store(controller, std::memory_order_release);
    const bool nested = inside_original_context;
    inside_original_context = true;
    original_context(controller, netid, uid, result);
    inside_original_context = nested;
    if (result) {
        AeContext prefix{};
        std::memcpy(&prefix, result, sizeof(prefix));
        decorate_context(&prefix);
        std::memcpy(result, &prefix, sizeof(prefix));
    }
}
uint32_t get_dns_network(const void *controller, uint32_t *netid, uint32_t uid) {
    network_controller.store(controller, std::memory_order_release);
    const uint32_t mark = original_dns_network(controller, netid, uid);
    if (!netid || inside_original_context)
        return mark;
    AeContext context{0, 0, *netid, mark, uid};
    decorate_context(&context);
    *netid = context.dns_netid;
    return context.dns_mark;
}

bool transfer(int fd, void *memory, size_t length, bool sending) {
    auto *data = static_cast<uint8_t *>(memory);
    while (length) {
        ssize_t n = sending ? send(fd, data, length, MSG_NOSIGNAL) : recv(fd, data, length, 0);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0)
            return false;
        data += n;
        length -= static_cast<size_t>(n);
    }
    return true;
}

void load_modern_bridge_fd(int socket_fd) {
    uint64_t tag = 0;
    iovec payload{&tag, sizeof(tag)};
    alignas(cmsghdr) char control[CMSG_SPACE(sizeof(int))]{};
    msghdr message{};
    message.msg_iov = &payload;
    message.msg_iovlen = 1;
    message.msg_control = control;
    message.msg_controllen = sizeof(control);
    const ssize_t count = recvmsg(socket_fd, &message, MSG_CMSG_CLOEXEC);
    int library_fd = -1;
    if (count == sizeof(tag) && tag == 0x41454c4942524152ULL && !(message.msg_flags & MSG_CTRUNC)) {
        auto *rights = CMSG_FIRSTHDR(&message);
        if (rights && rights->cmsg_level == SOL_SOCKET && rights->cmsg_type == SCM_RIGHTS &&
            rights->cmsg_len == CMSG_LEN(sizeof(int)))
            std::memcpy(&library_fd, CMSG_DATA(rights), sizeof(library_fd));
    }
    if (library_fd < 0) {
        __android_log_print(ANDROID_LOG_ERROR,
                            kTag,
                            "modern bridge FD receive failed: bytes=%zd flags=%x errno=%d",
                            count,
                            message.msg_flags,
                            errno);
        return;
    }
    if (modern_bridge) {
        close(library_fd);
        return;
    }
    android_dlextinfo options{};
    options.flags = ANDROID_DLEXT_USE_LIBRARY_FD;
    options.library_fd = library_fd;
    modern_bridge = android_dlopen_ext("libae_resolver29.so", RTLD_NOW | RTLD_LOCAL, &options);
    close(library_fd);
    if (!modern_bridge) {
        __android_log_print(ANDROID_LOG_ERROR, kTag, "modern bridge FD: %s", dlerror());
        return;
    }
}

const char *find_resolver_image(const ZygiskNextAPI *api) {
#if defined(__LP64__)
    const char *paths[] = {"/apex/com.android.resolv/lib64/libnetd_resolv.so",
                           "/apex/com.android.tethering/lib64/libnetd_resolv.so",
                           "/system/lib64/libnetd_resolv.so"};
#else
    const char *paths[] = {"/apex/com.android.resolv/lib/libnetd_resolv.so",
                           "/apex/com.android.tethering/lib/libnetd_resolv.so",
                           "/system/lib/libnetd_resolv.so"};
#endif
    for (const char *path : paths) {
        auto *symbols = api->newSymbolResolver(path, nullptr);
        if (!symbols)
            continue;
        const bool available =
            api->getBaseAddress(symbols) &&
            api->symbolLookup(symbols, "_Z18resolv_list_cachesv", false, nullptr);
        api->freeSymbolResolver(symbols);
        if (available)
            return path;
    }
    __android_log_print(ANDROID_LOG_ERROR, kTag, "loaded resolver cache interface not found");
    return nullptr;
}

void *background_runtime(void *) {
    char boot[PROP_VALUE_MAX]{};
    while (!__system_property_get("sys.boot_completed", boot) || std::strcmp(boot, "1"))
        sleep(1);
    // Module loading precedes main even when netd restarts after boot. Wait for
    // the real controller before fixing this process's capability snapshot.
    while (hook_installed.load() && !controller_constructed.load())
        sleep(1);
    if (platform_api >= 29)
        resolver_path = find_resolver_image(&runtime_api);
    if (hook_installed.load() && (platform_api < 29 || resolver_path))
        ae_query_install(
            &runtime_api, platform_api < 29 ? "/system/bin/netd" : resolver_path, platform_api);
    bool initialized = false;
    for (;;) {
        ae_runtime_tick();
        const int companion = runtime_api.connectCompanion(module_handle);
        if (companion < 0) {
            sleep(1);
            continue;
        }
        timeval timeout{2, 0};
        setsockopt(companion, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
        setsockopt(companion, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
        uint64_t nonce = 0x4145535445524900ULL | static_cast<uint64_t>(platform_api), response = 0;
        const bool connected = transfer(companion, &nonce, sizeof(nonce), true) &&
                               transfer(companion, &response, sizeof(response), false) &&
                               response == (nonce ^ 0x5a5a5a5a5a5a5a5aULL);
        if (connected) {
            // Consume the FD on every handshake. dlopen the bridge just once.
            if (platform_api >= 29)
                load_modern_bridge_fd(companion);
            if (!initialized) {
                if (hook_installed.load())
                    ae_backend_init(&runtime_api, platform_api, modern_bridge, resolver_path);
                uint32_t modes = 0, flags = ae_backend_ready()
                                                ? (AE_CAP_NETWORK_DISCOVERY | AE_CAP_DNS_ROUTES)
                                                : 0;
                // Publish capabilities only after context hooks, resolver access
                // and query lifetime tracking are ready. The supervisor/helper
                // checks BPF attachment compatibility at runtime.
                if (hook_installed.load() && controller_constructed.load() && ae_backend_ready() &&
                    ae_query_tracking_ready())
                    modes = platform_api >= 33 ? 7U : 3U;
                initialized = ae_runtime_init(
                    netd_instance, static_cast<uint32_t>(platform_api), modes, flags);
            }
            if (initialized)
                ae_runtime_serve(companion);
        }
        close(companion);
        sleep(1);
    }
}

void loaded(void *self, const ZygiskNextAPI *api) {
    runtime_api = *api;
    module_handle = self;
    netd_instance = (static_cast<uint64_t>(getpid()) << 32) | arc4random();
    char level[PROP_VALUE_MAX]{};
    __system_property_get("ro.build.version.sdk", level);
    platform_api = std::atoi(level);
    auto *symbols = api->newSymbolResolver("/system/bin/netd", nullptr);
    if (symbols) {
        void *target = api->symbolLookup(
            symbols,
            "_ZNK7android3net17NetworkController17getNetworkContextEjjP19android_net_context",
            false,
            nullptr);
        void *legacy_target =
            platform_api < 28
                ? api->symbolLookup(symbols,
                                    "_ZNK7android3net17NetworkController16getNetworkForDnsEPjj",
                                    false,
                                    nullptr)
                : nullptr;
        void *ctor1 =
            api->symbolLookup(symbols, "_ZN7android3net17NetworkControllerC1Ev", false, nullptr);
        void *ctor2 =
            api->symbolLookup(symbols, "_ZN7android3net17NetworkControllerC2Ev", false, nullptr);
        bool captured1 = false, captured2 = false, context_hooked = false;
        if (target && (platform_api >= 28 || legacy_target) && ctor1) {
            // Capture the controller after its real constructor completes.
            captured1 =
                api->inlineHook(ctor1,
                                reinterpret_cast<void *>(construct_controller1),
                                reinterpret_cast<void **>(&original_constructor1)) == ZN_SUCCESS;
            const bool separate_ctor2 = ctor2 && ctor2 != ctor1;
            if (captured1 && separate_ctor2)
                captured2 = api->inlineHook(ctor2,
                                            reinterpret_cast<void *>(construct_controller2),
                                            reinterpret_cast<void **>(&original_constructor2)) ==
                            ZN_SUCCESS;
            if (captured1 && (!separate_ctor2 || captured2))
                context_hooked =
                    api->inlineHook(target,
                                    reinterpret_cast<void *>(get_context),
                                    reinterpret_cast<void **>(&original_context)) == ZN_SUCCESS;
            bool installed = context_hooked;
            if (installed && legacy_target)
                installed =
                    api->inlineHook(legacy_target,
                                    reinterpret_cast<void *>(get_dns_network),
                                    reinterpret_cast<void **>(&original_dns_network)) == ZN_SUCCESS;
            if (!installed) {
                bool rollback_ok = true;
                if (context_hooked)
                    rollback_ok &= api->inlineUnhook(target) == ZN_SUCCESS;
                if (captured2)
                    rollback_ok &= api->inlineUnhook(ctor2) == ZN_SUCCESS;
                if (captured1)
                    rollback_ok &= api->inlineUnhook(ctor1) == ZN_SUCCESS;
                __android_log_print(
                    ANDROID_LOG_ERROR,
                    kTag,
                    rollback_ok ? "context hook installation failed; prior hooks removed"
                                : "context hook installation failed; hook removal incomplete");
            }
            hook_installed.store(installed);
        } else {
            __android_log_print(
                ANDROID_LOG_ERROR, kTag, "required NetworkController interface not found");
        }
        api->freeSymbolResolver(symbols);
    } else {
        __android_log_print(ANDROID_LOG_ERROR, kTag, "netd symbols unavailable");
    }
    __android_log_print(ANDROID_LOG_INFO,
                        kTag,
                        "loaded; API %s; context hook=%d; inactive",
                        level,
                        hook_installed.load());
    pthread_t thread;
    if (!pthread_create(&thread, nullptr, background_runtime, nullptr))
        pthread_detach(thread);
}

void companion_loaded() {
    __android_log_print(ANDROID_LOG_INFO, kTag, "companion loaded");
}
void companion_connected(int fd) {
    timeval timeout{2, 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    uint64_t nonce = 0;
    bool connected = false;
    if (transfer(fd, &nonce, sizeof(nonce), false) && (nonce & ~0xffULL) == 0x4145535445524900ULL) {
        const unsigned api = static_cast<unsigned>(nonce & 0xff);
        nonce ^= 0x5a5a5a5a5a5a5a5aULL;
        connected = transfer(fd, &nonce, sizeof(nonce), true);
        if (connected && api >= 29) {
            const int library =
                open("/data/adb/modules/zygisk-next-asterisk-enhance/lib/libae_resolver29.so",
                     O_RDONLY | O_CLOEXEC);
            if (library >= 0) {
                uint64_t tag = 0x41454c4942524152ULL;
                iovec payload{&tag, sizeof(tag)};
                alignas(cmsghdr) char control[CMSG_SPACE(sizeof(int))]{};
                msghdr message{};
                message.msg_iov = &payload;
                message.msg_iovlen = 1;
                message.msg_control = control;
                message.msg_controllen = sizeof(control);
                auto *rights = CMSG_FIRSTHDR(&message);
                rights->cmsg_level = SOL_SOCKET;
                rights->cmsg_type = SCM_RIGHTS;
                rights->cmsg_len = CMSG_LEN(sizeof(int));
                std::memcpy(CMSG_DATA(rights), &library, sizeof(library));
                connected = sendmsg(fd, &message, MSG_NOSIGNAL) == sizeof(tag);
                close(library);
            } else {
                connected = false;
                __android_log_print(ANDROID_LOG_ERROR, kTag, "open resolver bridge: %d", errno);
            }
        }
    }
    if (connected)
        ae_broker_serve(fd);
    close(fd);
}
} // namespace

bool ae_original_dns_mark(uint32_t network, uint32_t *mark) {
    const void *controller = network_controller.load(std::memory_order_acquire);
    if (!mark || !controller || !original_context || !hook_installed.load() || !network ||
        network > 0xffffU)
        return false;
    // Platform contexts append flags, qhook or pid to the stable 20-byte prefix.
    alignas(8) uint8_t context[64]{};
    const bool nested = inside_original_context;
    inside_original_context = true;
    original_context(controller, network, 0, context);
    inside_original_context = nested;
    AeContext prefix{};
    std::memcpy(&prefix, context, sizeof(prefix));
    if (prefix.dns_netid != network || prefix.uid || (prefix.dns_mark & AE_MARK_MASK))
        return false;
    *mark = prefix.dns_mark;
    return true;
}

extern "C" {
__attribute__((visibility("default"), used)) ZygiskNextModule zn_module{ZYGISK_NEXT_API_VERSION,
                                                                        loaded};
__attribute__((visibility("default"), used)) ZygiskNextCompanionModule zn_companion_module{
    ZYGISK_NEXT_API_VERSION, companion_loaded, companion_connected};
}
