// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0

#include "resolver_backend.h"
#include "query_lifetime.h"
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
using Read29 = int (*)(uint32_t, AeDnsConfig *);
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
int configure_guard26(unsigned id,
                      const char **servers,
                      unsigned count,
                      const char *domains,
                      const Params26 *params) {
    if (!candidate(id))
        return original_configure26(id, servers, count, domains, params);
    pthread_mutex_lock(&gate);
    const int result = find(id) ? EBUSY : original_configure26(id, servers, count, domains, params);
    pthread_mutex_unlock(&gate);
    return result;
}
void delete_guard26(unsigned id) {
    if (!candidate(id)) {
        original_delete26(id);
        return;
    }
    pthread_mutex_lock(&gate);
    if (!find(id))
        original_delete26(id);
    pthread_mutex_unlock(&gate);
}
int legacy_info(uint32_t id, AeDnsConfig *output) {
    int count = 0, domain_count = 0;
    sockaddr_storage servers[4]{};
    char domains[6][256]{};
    Params26 params{};
    Stats26 stats[4]{};
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
        return !error && *owned ? 0 : 2;
    }
    const int reserved = reserve29(id);
    if (reserved) {
        pthread_mutex_unlock(&gate);
        return reserved == -EEXIST ? 1 : 2;
    }
    slot->id = id;
    slot->network = network;
    slot->config = config;
    *owned = 1;
    const int error = configure29(id, &config);
    pthread_mutex_unlock(&gate);
    return error ? 2 : 0;
}
int check(void *, uint32_t network, uint32_t id) {
    // The actor is the sole caller/writer; guards only inspect IDs under gate.
    const Record *record = find(id);
    if (!record || record->network != network)
        return 1;
    AeDnsConfig original{}, copy{};
    return ae_backend_read(network, &original) || ae_backend_read(id, &copy) ||
           std::memcmp(&original, &record->config, sizeof(original)) ||
           std::memcmp(&copy, &record->config, sizeof(copy));
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
int networks(void *, uint32_t *output, uint32_t capacity) {
    return ae_backend_networks(output, capacity);
}
int routes(void *, uint32_t network, uint32_t id, AeDnsRoute *output, uint32_t capacity) {
    const Record *record = find(id);
    if (!output || !record || check(nullptr, network, id) || !record->config.server_count ||
        record->config.server_count > capacity) {
        __android_log_print(ANDROID_LOG_ERROR,
                            "AsteriskEnhance",
                            "cache prepare: routes config invalid network=%u cache=%u",
                            network,
                            id);
        return -EINVAL;
    }
    uint32_t mark = 0;
    if (!ae_original_dns_mark(network, &mark)) {
        __android_log_print(ANDROID_LOG_ERROR,
                            "AsteriskEnhance",
                            "cache prepare: DNS mark unavailable network=%u",
                            network);
        return -ENOTSUP;
    }
    for (uint32_t i = 0; i < record->config.server_count; ++i) {
        AeDnsRoute route{};
        route.network_id = network;
        route.original_mark = mark;
        char server[sizeof(record->config.servers[i])];
        std::memcpy(server, record->config.servers[i], sizeof(server));
        if (!std::memchr(server, 0, sizeof(server)))
            return -EINVAL;
        char *scope = std::strchr(server, '%');
        if (scope) {
            *scope++ = 0;
            if (!*scope)
                return -EINVAL;
            char *end = nullptr;
            errno = 0;
            const unsigned long value = std::strtoul(scope, &end, 10);
            if (!errno && *scope >= '0' && *scope <= '9' && !*end && value <= UINT32_MAX)
                route.scope_id = static_cast<uint32_t>(value);
            else
                route.scope_id = if_nametoindex(scope);
            if (!route.scope_id)
                return -EINVAL;
        }
        if (inet_pton(AF_INET, server, route.address) == 1) {
            if (scope)
                return -EINVAL;
            route.family = 4;
        } else if (inet_pton(AF_INET6, server, route.address) == 1)
            route.family = 6;
        else
            return -EINVAL;
        output[i] = route;
    }
    return static_cast<int>(record->config.server_count);
}
uint64_t now_ms(void *) {
    timespec now{};
    if (clock_gettime(CLOCK_BOOTTIME, &now))
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
    } else if (sdk >= 29 && bridge) {
        if (!api || !resolver_path)
            return false;
        auto *resolver = api->newSymbolResolver(resolver_path, nullptr);
        if (!resolver)
            return false;
        list29 = api->symbolLookup(resolver, "_Z18resolv_list_cachesv", false, nullptr);
        api->freeSymbolResolver(resolver);
        read29 = reinterpret_cast<Read29>(dlsym(bridge, "ae_resolver_read_config"));
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
    return {nullptr, create, check, destroy, inflight, now_ms, networks, routes};
}
int ae_backend_read(uint32_t network, AeDnsConfig *output) {
    if (!ready || !output)
        return -ENOTSUP;
    return platform < 29 ? legacy_info(network, output) : read29(network, output);
}
int ae_backend_networks(uint32_t *output, uint32_t capacity) {
    if (!ready || !output || !capacity)
        return -ENOTSUP;
    if (platform >= 29) {
        const int available = ae_platform_list_caches(list29, output, capacity);
        if (available < 0)
            return available;
        uint32_t count = 0;
        for (int i = 0; i < available; ++i) {
            AeDnsConfig config{};
            const int error = read29(output[i], &config);
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
                return error;
            }
            output[count++] = output[i];
        }
        return static_cast<int>(count);
    }
    // The legacy public stats API is a native, mutex-protected lookup. Enumerate
    // the bounded real-network domain without reading private cache structures.
    uint32_t count = 0;
    for (uint32_t id = 1; id <= 0xffffU; ++id) {
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
            return error;
        }
        if (count == capacity) {
            __android_log_print(ANDROID_LOG_ERROR,
                                "AsteriskEnhance",
                                "cache discovery: capacity exceeded capacity=%u",
                                capacity);
            return -EOVERFLOW;
        }
        output[count++] = id;
    }
    if (!count)
        __android_log_print(ANDROID_LOG_WARN,
                            "AsteriskEnhance",
                            "cache discovery: no configured DNS networks; resolver not ready");
    return static_cast<int>(count);
}
