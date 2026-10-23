// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0

#include "resolver_backend.h"
#include "query_lifetime.h"
#include "runtime.h"
#include <arpa/inet.h>
#include <android/log.h>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <dlfcn.h>
#include <cstdlib>
#include <net/if.h>
#include <pthread.h>
#include <time.h>

extern "C" int ae_platform_list_caches(void *, uint32_t *, uint32_t);
extern "C" int ae_platform_private_dns28(void *, uint32_t);
extern "C" int ae_platform_private_dns27(void *, uint32_t, const sockaddr_storage *, uint32_t);
static int discover(uint32_t *, uint32_t, const AeCacheBinding *, uint32_t);

namespace {
struct Params26 {
    uint16_t sample_validity;
    uint8_t threshold, min_samples, max_samples;
};
struct Sample26 {
    time_t at;
    uint16_t rtt;
    uint8_t rcode;
};
struct Stats26 {
    Sample26 samples[64];
    uint8_t count, next;
};
static_assert(sizeof(Stats26) == (sizeof(time_t) == 8 ? 1032U : 516U));
using Stats =
    int (*)(unsigned, int *, sockaddr_storage *, int *, char (*)[256], Params26 *, Stats26 *);
using Configure26 = int (*)(unsigned, const char **, unsigned, const char *, const Params26 *);
using Delete26 = void (*)(unsigned);
using Read29 = int (*)(uint32_t, AeDnsConfig *, uint32_t *);
using Configure29 = int (*)(uint32_t, const AeDnsConfig *);
using Cache29 = int (*)(uint32_t);
Stats stats26 = nullptr;
Configure26 original_configure26 = nullptr;
Delete26 original_delete26 = nullptr;
Read29 read29 = nullptr;
Configure29 configure29 = nullptr;
Cache29 reserve29 = nullptr, destroy29 = nullptr;
void *list29 = nullptr;
void *private_dns28 = nullptr;
void *private_dns27 = nullptr;
int platform = 0;
bool ready = false;
thread_local AeFailure last_failure{};
int failure(uint32_t stage, uint32_t reason, int error, uint32_t network) {
    last_failure = {stage, reason, error, network};
    __android_log_print(ANDROID_LOG_ERROR, "AsteriskEnhance",
                        "DNS prepare failure: stage=%u reason=%u error=%d network=%u",
                        stage, reason, error, network);
    return error;
}
AeFailure failure_detail(void *) { return last_failure; }
pthread_mutex_t gate = PTHREAD_MUTEX_INITIALIZER;
struct Record {
    uint32_t id = 0, network = 0;
    AeDnsConfig config{};
};
Record records[AE_MAX_NETWORKS];
bool candidate(uint32_t id) {
    return id >= 0x40000000U && id <= 0x4000ffffU;
}
Record *find(uint32_t id) {
    for (auto &record : records)
        if (record.id == id)
            return &record;
    return nullptr;
}
// API26-28 real networks that may own a resolver cache. The configure/delete
// hooks update it while serialized with the original call, and it is seeded
// once after they are installed, so discovery never probes the full netId range.
// Recursive: an OEM resolver that nests configure/delete cannot self-deadlock.
pthread_mutex_t inventory = PTHREAD_RECURSIVE_MUTEX_INITIALIZER_NP;
uint32_t known_networks[0x10000U / 32U];
void set_known(uint32_t id, bool present) {
    if (!id || id > 0xffffU)
        return;
    const uint32_t bit = 1U << (id % 32U);
    if (present)
        known_networks[id / 32U] |= bit;
    else
        known_networks[id / 32U] &= ~bit;
}
int configure_guard26(unsigned id,
                      const char **servers,
                      unsigned count,
                      const char *domains,
                      const Params26 *params) {
    if (!candidate(id)) {
        pthread_mutex_lock(&inventory);
        const int result = original_configure26(id, servers, count, domains, params);
        set_known(id, true); // A failed update may still leave an older cache.
        pthread_mutex_unlock(&inventory);
        ae_runtime_network_changed();
        return result;
    }
    pthread_mutex_lock(&gate);
    const int result = find(id) ? EBUSY : original_configure26(id, servers, count, domains, params);
    pthread_mutex_unlock(&gate);
    return result;
}
void delete_guard26(unsigned id) {
    if (!candidate(id)) {
        pthread_mutex_lock(&inventory);
        original_delete26(id);
        set_known(id, false);
        pthread_mutex_unlock(&inventory);
        ae_runtime_network_changed();
        return;
    }
    pthread_mutex_lock(&gate);
    if (!find(id))
        original_delete26(id);
    pthread_mutex_unlock(&gate);
}
using ResolverConfigure = int (*)(void *, const void *);
using ResolverConfigure29 = int (*)(void *, const void *, const void *);
ResolverConfigure original_resolver_configure = nullptr;
ResolverConfigure29 original_resolver_configure29 = nullptr;
using ResolverDelete = void (*)(void *, unsigned);
ResolverDelete original_resolver_delete = nullptr;
using PrefixReport = bool (*)(void *, unsigned, bool, const void *);
using PrefixSet = int (*)(void *, unsigned, const void *);
PrefixReport original_prefix_report = nullptr;
PrefixSet original_prefix_set = nullptr;
bool prefix_reported(void *controller, unsigned network, bool added, const void *prefix) {
    const bool result = original_prefix_report(controller, network, added, prefix);
    ae_runtime_network_changed();
    return result;
}
int prefix_set(void *controller, unsigned network, const void *prefix) {
    const int result = original_prefix_set(controller, network, prefix);
    ae_runtime_network_changed();
    return result;
}
// ResolverParamsParcel is an NDK parcelable without virtual members; netId is
// its first AIDL field in every revision.
uint32_t parcel_network(const void *params) {
    int32_t network = 0;
    std::memcpy(&network, params, sizeof(network));
    return static_cast<uint32_t>(network);
}
int configure_changed(void *controller, const void *params) {
    const int result = original_resolver_configure(controller, params);
    // Isolated caches are configured by PREPARE itself, not by a topology change.
    if (!params || !candidate(parcel_network(params)))
        ae_runtime_network_changed();
    return result;
}
int configure_changed29(void *controller, const void *params, const void *fingerprints) {
    const int result = original_resolver_configure29(controller, params, fingerprints);
    if (!params || !candidate(parcel_network(params)))
        ae_runtime_network_changed();
    return result;
}
void delete_changed(void *controller, unsigned id) {
    original_resolver_delete(controller, id);
    if (!candidate(id))
        ae_runtime_network_changed();
}
int legacy_info(uint32_t id, AeDnsConfig *output) {
    int count = 0, domain_count = 0;
    sockaddr_storage servers[4]{};
    char domains[6][256]{};
    Params26 params{};
    Stats26 stats[4]; // Output only and never read; skip clearing 4 KiB per call.
    const int revision = stats26(id, &count, servers, &domain_count, domains, &params, stats);
    if (revision < 0)
        return -ENOENT;
    if (!output)
        return 0; // An empty existing cache is still a collision.
    if (platform == 28 && ae_platform_private_dns28(private_dns28, id))
        return -ENOTSUP;
    if (!count)
        return -ENOENT; // No DNS configuration to clone; still a collision above.
    if (count < 1 || count > 4 || domain_count < 0 || domain_count > 6)
        return -ENOTSUP;
    if (platform == 27 &&
        ae_platform_private_dns27(private_dns27, id, servers, static_cast<uint32_t>(count)))
        return -ENOTSUP;
    AeDnsConfig config{};
    config.server_count = static_cast<uint32_t>(count);
    config.domain_count = static_cast<uint32_t>(domain_count);
    for (int i = 0; i < count; ++i) {
        const void *address = nullptr;
        if (servers[i].ss_family == AF_INET)
            address = &reinterpret_cast<const sockaddr_in *>(&servers[i])->sin_addr;
        else if (servers[i].ss_family == AF_INET6)
            address = &reinterpret_cast<const sockaddr_in6 *>(&servers[i])->sin6_addr;
        else
            return -ENOTSUP;
        if (!inet_ntop(servers[i].ss_family, address, config.servers[i], sizeof(config.servers[i])))
            return -errno;
        if (servers[i].ss_family == AF_INET6) {
            const unsigned scope =
                reinterpret_cast<const sockaddr_in6 *>(&servers[i])->sin6_scope_id;
            if (scope) {
                const size_t length = std::strlen(config.servers[i]);
                std::snprintf(
                    config.servers[i] + length, sizeof(config.servers[i]) - length, "%%%u", scope);
            }
        }
    }
    for (int i = 0; i < domain_count; ++i) {
        const size_t length = strnlen(domains[i], sizeof(domains[i]));
        if (length == sizeof(domains[i]))
            return -EOVERFLOW;
        std::memcpy(config.domains[i], domains[i], length + 1);
    }
    config.parameters[0] = params.sample_validity;
    config.parameters[1] = params.threshold;
    config.parameters[2] = params.min_samples;
    config.parameters[3] = params.max_samples;
    *output = config;
    return 0;
}
// Lightweight per-query API27 state check: server presence and TLS use only.
// Configuration changes still arrive through the configure/delete hooks.
bool legacy_tls27_blocked(uint32_t id) {
    int count = 0, domain_count = 0;
    sockaddr_storage servers[4]{};
    char domains[6][256];
    Params26 params{};
    Stats26 stats[4];
    if (stats26(id, &count, servers, &domain_count, domains, &params, stats) < 0 || count < 1 ||
        count > 4)
        return true;
    return ae_platform_private_dns27(private_dns27, id, servers, static_cast<uint32_t>(count)) != 0;
}
int legacy_configure(uint32_t id, const AeDnsConfig &config) {
    const char *servers[4]{};
    if (!config.server_count || config.server_count > 4 || config.domain_count > 6)
        return -EINVAL;
    for (uint32_t i = 0; i < config.server_count; ++i)
        servers[i] = config.servers[i];
    char domains[256]{};
    size_t written = 0;
    for (uint32_t i = 0; i < config.domain_count; ++i) {
        const size_t length = strnlen(config.domains[i], sizeof(config.domains[i]));
        if (length == sizeof(config.domains[i]) ||
            length + (i ? 1 : 0) >= sizeof(domains) - written)
            return -EOVERFLOW;
        if (i)
            domains[written++] = ' ';
        std::memcpy(domains + written, config.domains[i], length);
        written += length;
    }
    const Params26 params{static_cast<uint16_t>(config.parameters[0]),
                          static_cast<uint8_t>(config.parameters[1]),
                          static_cast<uint8_t>(config.parameters[2]),
                          static_cast<uint8_t>(config.parameters[3])};
    const int result = original_configure26(id, servers, config.server_count, domains, &params);
    return result > 0 ? -result : result;
}
int create(void *, uint32_t network, uint32_t id, uint32_t *owned) {
    last_failure = {};
    if (!owned)
        return 2;
    *owned = 0;
    if (!ready || !candidate(id) || !network || network > 0xffffU)
        return 2;
    AeDnsConfig config{};
    const int read_error = ae_backend_read(network, &config);
    if (read_error) {
        __android_log_print(ANDROID_LOG_ERROR,
                            "AsteriskEnhance",
                            "cache prepare: read network=%u error=%d",
                            network,
                            read_error);
        return 2;
    }
    pthread_mutex_lock(&gate);
    if (find(id)) {
        pthread_mutex_unlock(&gate);
        return 1;
    }
    Record *slot = nullptr;
    for (auto &record : records)
        if (!record.id) {
            slot = &record;
            break;
        }
    if (!slot) {
        pthread_mutex_unlock(&gate);
        failure(AE_FAIL_RESERVE, AE_REASON_CAPACITY, -ENOSPC, network);
        return 2;
    }
    if (platform < 29) {
        if (!legacy_info(id, nullptr)) {
            pthread_mutex_unlock(&gate);
            return 1;
        }
        // AOSP API 26 creates cache entries only in set_nameservers_for_net.
        // The configure/delete hooks share this gate for the candidate range.
        const int error = legacy_configure(id, config);
        if (!legacy_info(id, nullptr)) {
            slot->id = id;
            slot->network = network;
            slot->config = config;
            *owned = 1;
        }
        pthread_mutex_unlock(&gate);
        if (error || !*owned)
            __android_log_print(ANDROID_LOG_ERROR,
                                "AsteriskEnhance",
                                "cache prepare: configure network=%u cache=%u error=%d owned=%u",
                                network,
                                id,
                                error,
                                *owned);
        if (error || !*owned)
            failure(AE_FAIL_CONFIGURE, AE_REASON_BACKEND, error ? error : -EIO, network);
        return !error && *owned ? 0 : 2;
    }
    const int reserved = reserve29(id);
    if (reserved) {
        pthread_mutex_unlock(&gate);
        if (reserved != -EEXIST)
            failure(AE_FAIL_RESERVE, AE_REASON_BACKEND, reserved, network);
        return reserved == -EEXIST ? 1 : 2;
    }
    slot->id = id;
    slot->network = network;
    slot->config = config;
    *owned = 1;
    const int error = configure29(id, &config);
    pthread_mutex_unlock(&gate);
    if (error)
        failure(AE_FAIL_CONFIGURE, AE_REASON_BACKEND, error, network);
    return error ? 2 : 0;
}
int check_config(uint32_t network, uint32_t id, const AeDnsConfig &original) {
    last_failure = {};
    // The actor is the sole caller/writer; guards only inspect IDs under gate.
    const Record *record = find(id);
    if (!record || record->network != network) {
        failure(AE_FAIL_CHECK, AE_REASON_BACKEND, -ENOENT, network);
        return 1;
    }
    AeDnsConfig copy{};
    if (ae_backend_read(id, &copy))
        return 1;
    if (std::memcmp(&original, &record->config, sizeof(original)))
        return failure(AE_FAIL_CHECK, AE_REASON_CHANGED, -EAGAIN, network);
    if (std::memcmp(&copy, &record->config, sizeof(copy)))
        return failure(AE_FAIL_CHECK, AE_REASON_BACKEND, -EIO, network);
    return 0;
}
int check(void *, uint32_t network, uint32_t id) {
    AeDnsConfig original{};
    if (ae_backend_read(network, &original))
        return 1;
    return check_config(network, id, original);
}
int validate(void *, const AeCacheBinding *bindings, uint32_t count, uint32_t discovered) {
    if (discovered) {
        uint32_t networks[AE_MAX_NETWORKS];
        // Configurations read while discovering are consumed immediately, not
        // cached for another request. Isolated caches are still checked too.
        const int current = discover(networks, AE_MAX_NETWORKS, bindings, count);
        return current < 0 || static_cast<uint32_t>(current) != count;
    }
    for (uint32_t i = 0; i < count; ++i)
        if (check(nullptr, bindings[i].network_id, bindings[i].cache_id))
            return 1;
    return 0;
}
int destroy(void *, uint32_t id) {
    pthread_mutex_lock(&gate);
    Record *record = find(id);
    if (!ready || !record) {
        pthread_mutex_unlock(&gate);
        return 1;
    }
    int error = 0;
    if (platform < 29) {
        original_delete26(id);
        error = legacy_info(id, nullptr) == -ENOENT ? 0 : -EIO;
    } else {
        error = destroy29(id);
        if (error == -ENOENT)
            error = 0; // Only an ID already in our ownership table.
    }
    if (!error)
        record->id = 0;
    pthread_mutex_unlock(&gate);
    return error ? 1 : 0;
}
uint32_t inflight(void *) {
    return ae_query_inflight();
}
void drain_wait(void *) {
    ae_query_wait_drain();
}
int networks(void *, uint32_t *output, uint32_t capacity) {
    return ae_backend_networks(output, capacity);
}
int routes(void *, uint32_t network, uint32_t id, AeDnsRoute *output, uint32_t capacity) {
    last_failure = {};
    const Record *record = find(id);
    if (!output || !record || check(nullptr, network, id) || !record->config.server_count ||
        record->config.server_count > capacity) {
        __android_log_print(ANDROID_LOG_ERROR,
                            "AsteriskEnhance",
                            "cache prepare: routes config invalid network=%u cache=%u",
                            network,
                            id);
        if (!last_failure.stage)
            failure(AE_FAIL_ROUTES, AE_REASON_INVALID_CONFIG, -EINVAL, network);
        return -EINVAL;
    }
    uint32_t mark = 0;
    const int mark_error = ae_original_dns_mark(network, &mark);
    if (mark_error) {
        __android_log_print(ANDROID_LOG_ERROR,
                            "AsteriskEnhance",
                            "cache prepare: DNS mark unavailable network=%u error=%d",
                            network,
                            mark_error);
        return failure(AE_FAIL_ROUTES,
                       mark_error == -EAGAIN ? AE_REASON_CHANGED : AE_REASON_BACKEND,
                       mark_error,
                       network);
    }
    // Every rejected server keeps a precise failure for the supervisor report.
    const auto invalid_route = [network] {
        return failure(AE_FAIL_ROUTES, AE_REASON_INVALID_CONFIG, -EINVAL, network);
    };
    for (uint32_t i = 0; i < record->config.server_count; ++i) {
        AeDnsRoute route{};
        route.network_id = network;
        route.original_mark = mark;
        char server[sizeof(record->config.servers[i])];
        std::memcpy(server, record->config.servers[i], sizeof(server));
        if (!std::memchr(server, 0, sizeof(server)))
            return invalid_route();
        char *scope = std::strchr(server, '%');
        if (scope) {
            *scope++ = 0;
            if (!*scope)
                return invalid_route();
            char *end = nullptr;
            errno = 0;
            const unsigned long value = std::strtoul(scope, &end, 10);
            if (!errno && *scope >= '0' && *scope <= '9' && !*end && value <= UINT32_MAX)
                route.scope_id = static_cast<uint32_t>(value);
            else
                route.scope_id = if_nametoindex(scope);
            if (!route.scope_id)
                return invalid_route();
        }
        if (inet_pton(AF_INET, server, route.address) == 1) {
            if (scope)
                return invalid_route();
            route.family = 4;
        } else if (inet_pton(AF_INET6, server, route.address) == 1)
            route.family = 6;
        else
            return invalid_route();
        output[i] = route;
    }
    return static_cast<int>(record->config.server_count);
}
uint64_t now_ms(void *) {
    timespec now{};
    if (clock_gettime(CLOCK_MONOTONIC, &now))
        return UINT64_MAX;
    return static_cast<uint64_t>(now.tv_sec) * 1000U +
           static_cast<uint64_t>(now.tv_nsec) / 1000000U;
}
} // namespace
bool ae_backend_init(const ZygiskNextAPI *api, int sdk, void *bridge, const char *resolver_path) {
    if (ready)
        return true;
    platform = sdk;
    if (sdk >= 26 && sdk <= 28) {
        if (sdk == 27 || sdk == 28) {
            if (!api)
                return false;
            auto *symbols = api->newSymbolResolver("/system/bin/netd", nullptr);
            if (!symbols)
                return false;
            if (sdk == 28)
                private_dns28 =
                    api->symbolLookup(symbols,
                                      "_ZNK7android3net18ResolverController19getPrivateDnsStatusEj",
                                      false,
                                      nullptr);
            else
                private_dns27 =
                    api->symbolLookup(symbols,
                                      "_ZN7android3net18ResolverController12shouldUseTlsEjRK25__"
                                      "kernel_sockaddr_storagePS2_PNSt3__13setINS6_6vectorIhNS6_"
                                      "9allocatorIhEEEENS6_4lessISB_EENS9_ISB_EEEE",
                                      false,
                                      nullptr);
            api->freeSymbolResolver(symbols);
            if (sdk == 28 ? !private_dns28 : !private_dns27)
                return false;
        }
        stats26 =
            reinterpret_cast<Stats>(dlsym(RTLD_DEFAULT, "android_net_res_stats_get_info_for_net"));
        void *configure = dlsym(RTLD_DEFAULT, "_resolv_set_nameservers_for_net");
        void *remove = dlsym(RTLD_DEFAULT, "_resolv_delete_cache_for_net");
        if (!api || !stats26 || !configure || !remove)
            return false;
        if (api->inlineHook(configure,
                            reinterpret_cast<void *>(configure_guard26),
                            reinterpret_cast<void **>(&original_configure26)) != ZN_SUCCESS)
            return false;
        if (api->inlineHook(remove,
                            reinterpret_cast<void *>(delete_guard26),
                            reinterpret_cast<void **>(&original_delete26)) != ZN_SUCCESS) {
            api->inlineUnhook(configure);
            return false;
        }
        // Seed once, after the hooks track later changes. Each probe holds the
        // inventory lock, so a concurrent configure/delete of that ID is ordered
        // with it and the bitmap matches the resolver's final cache set.
        for (uint32_t id = 1; id <= 0xffffU; ++id) {
            pthread_mutex_lock(&inventory);
            if (!legacy_info(id, nullptr))
                set_known(id, true);
            pthread_mutex_unlock(&inventory);
        }
    } else if (sdk >= 29 && bridge) {
        if (!api || !resolver_path)
            return false;
        auto *resolver = api->newSymbolResolver(resolver_path, nullptr);
        if (!resolver)
            return false;
        list29 = api->symbolLookup(resolver, "_Z18resolv_list_cachesv", false, nullptr);
        const char *configure_symbol =
            sdk == 29 ? "_ZN7android3net18ResolverController24setResolverConfigurationERKN4aidl7and"
                        "roid3net20ResolverParamsParcelERKNSt3__13setINS8_6vectorIhNS8_"
                        "9allocatorIhEEEENS8_4lessISD_EENSB_ISD_EEEE"
                      : "_ZN7android3net18ResolverController24setResolverConfigurationERKN4aidl7and"
                        "roid3net20ResolverParamsParcelE";
        void *configure = api->symbolLookup(resolver, configure_symbol, false, nullptr);
        // Hook the controller entry point, as for configuration changes. On x86_64,
        // the low-level cache function can start with an FS-relative stack-canary
        // load that the inline hook provider truncates while building its trampoline.
        void *remove = api->symbolLookup(
            resolver,
            "_ZN7android3net18ResolverController19destroyNetworkCacheEj",
            false,
            nullptr);
        void *report_prefix = api->symbolLookup(resolver,
                                                "_ZN7android3net18Dns64Configuration23reportNat64Pr"
                                                "efixStatusEjbRKNS_9netdutils8IPPrefixE",
                                                false,
                                                nullptr);
        void *set_prefix =
            sdk >= 30
                ? api->symbolLookup(
                      resolver,
                      "_ZN7android3net18Dns64Configuration11setPrefix64EjRKNS_9netdutils8IPPrefixE",
                      false,
                      nullptr)
                : nullptr;
        api->freeSymbolResolver(resolver);
        if (!configure || !remove || !report_prefix || (sdk >= 30 && !set_prefix))
            return false;
        void *replacement = sdk == 29 ? reinterpret_cast<void *>(configure_changed29)
                                      : reinterpret_cast<void *>(configure_changed);
        void **original = sdk == 29 ? reinterpret_cast<void **>(&original_resolver_configure29)
                                    : reinterpret_cast<void **>(&original_resolver_configure);
        struct Hook {
            void *target, *replacement;
            void **original;
        } hooks[] = {{configure, replacement, original},
                     {remove,
                      reinterpret_cast<void *>(delete_changed),
                      reinterpret_cast<void **>(&original_resolver_delete)},
                     {report_prefix,
                      reinterpret_cast<void *>(prefix_reported),
                      reinterpret_cast<void **>(&original_prefix_report)},
                     {set_prefix,
                      reinterpret_cast<void *>(prefix_set),
                      reinterpret_cast<void **>(&original_prefix_set)}};
        const unsigned count = sdk >= 30 ? 4 : 3;
        for (unsigned i = 0; i < count; ++i) {
            if (api->inlineHook(hooks[i].target, hooks[i].replacement, hooks[i].original) !=
                ZN_SUCCESS) {
                while (i) {
                    --i;
                    api->inlineUnhook(hooks[i].target);
                }
                return false;
            }
        }
        read29 = reinterpret_cast<Read29>(dlsym(bridge, "ae_resolver_read_config_detail"));
        reserve29 = reinterpret_cast<Cache29>(dlsym(bridge, "ae_resolver_reserve"));
        configure29 = reinterpret_cast<Configure29>(dlsym(bridge, "ae_resolver_configure"));
        destroy29 = reinterpret_cast<Cache29>(dlsym(bridge, "ae_resolver_destroy"));
        if (!list29 || !read29 || !reserve29 || !configure29 || !destroy29)
            return false;
    } else
        return false;
    ready = true;
    return true;
}
bool ae_backend_ready() {
    return ready;
}
AeActorBackend ae_backend_callbacks() {
    return {nullptr,
            create,
            check,
            destroy,
            inflight,
            now_ms,
            networks,
            routes,
            failure_detail,
            validate,
            drain_wait};
}
int ae_backend_read(uint32_t network, AeDnsConfig *output) {
    last_failure = {};
    if (!ready || !output)
        return -ENOTSUP;
    uint32_t reason = AE_REASON_BACKEND;
    const int error = platform < 29 ? legacy_info(network, output) : read29(network, output, &reason);
    if (!error)
        return 0;
    if (error == -ENOENT) reason = AE_REASON_NOT_READY;
    return failure(AE_FAIL_READ, reason, error, network);
}
bool ae_backend_tls27_blocked(uint32_t network) {
    return !ready || platform != 27 || legacy_tls27_blocked(network);
}
int ae_backend_networks(uint32_t *output, uint32_t capacity) {
    return discover(output, capacity, nullptr, 0);
}
static int discover(uint32_t *output, uint32_t capacity,
                    const AeCacheBinding *expected, uint32_t expected_count) {
    last_failure = {};
    if (!ready || !output || !capacity)
        return -ENOTSUP;
    if (platform >= 29) {
        const int available = ae_platform_list_caches(list29, output, capacity);
        if (available < 0)
            return failure(AE_FAIL_DISCOVER, AE_REASON_BACKEND, available, 0);
        uint32_t count = 0;
        for (int i = 0; i < available; ++i) {
            AeDnsConfig config{};
            uint32_t reason = AE_REASON_BACKEND;
            const int error = read29(output[i], &config, &reason);
            // Android also keeps caches for networks without configured DNS.
            // Keep them reserved, but do not clone them into a policy generation.
            if (error == -ENOENT)
                continue;
            if (error) {
                __android_log_print(ANDROID_LOG_ERROR,
                                    "AsteriskEnhance",
                                    "cache discovery: read network=%u error=%d",
                                    output[i],
                                    error);
                return failure(AE_FAIL_READ, reason, error, output[i]);
            }
            if (expected && (count >= expected_count || expected[count].network_id != output[i] ||
                check_config(output[i], expected[count].cache_id, config)))
                return -EAGAIN;
            output[count++] = output[i];
        }
        return static_cast<int>(count);
    }
    // The legacy public stats API is a native, mutex-protected lookup. Read only
    // networks the hooks have seen, without reading private cache structures.
    // Changes after this snapshot signal a resolver event and a fresh check.
    uint32_t known[sizeof(known_networks) / sizeof(known_networks[0])];
    pthread_mutex_lock(&inventory);
    std::memcpy(known, known_networks, sizeof(known));
    pthread_mutex_unlock(&inventory);
    uint32_t count = 0;
    for (uint32_t id = 1; id <= 0xffffU; ++id) {
        if (!(known[id / 32U] & (1U << (id % 32U))))
            continue;
        AeDnsConfig config{};
        const int error = legacy_info(id, &config);
        if (error == -ENOENT)
            continue;
        if (error) {
            __android_log_print(ANDROID_LOG_ERROR,
                                "AsteriskEnhance",
                                "cache discovery: read network=%u error=%d",
                                id,
                                error);
            return failure(AE_FAIL_READ, AE_REASON_BACKEND, error, id);
        }
        if (count == capacity) {
            __android_log_print(ANDROID_LOG_ERROR,
                                "AsteriskEnhance",
                                "cache discovery: capacity exceeded capacity=%u",
                                capacity);
            return failure(AE_FAIL_DISCOVER, AE_REASON_CAPACITY, -EOVERFLOW, 0);
        }
        if (expected && (count >= expected_count || expected[count].network_id != id ||
            check_config(id, expected[count].cache_id, config)))
            return -EAGAIN;
        output[count++] = id;
    }
    return static_cast<int>(count);
}
