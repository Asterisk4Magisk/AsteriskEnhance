// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0

#include "resolver_bridge.h"
#include <aidl/android/net/BpDnsResolver.h>
#include <aidl/android/net/ResolverParamsParcel.h>
#include <cerrno>
#include <climits>
#include <cstring>
#include <dlfcn.h>

namespace {
using aidl::android::net::BpDnsResolver;
using aidl::android::net::ResolverParamsParcel;
int status_error(const ndk::ScopedAStatus &status) {
    if (status.isOk())
        return 0;
    const int service = status.getServiceSpecificError();
    return service > 0 ? -service : service < 0 ? service : -EIO;
}
ndk::SpAIBinder service() {
    // Service-manager entrypoints are platform APIs, not in the application
    // NDK stub library. Resolve the documented C signature in privileged netd.
    using CheckService = AIBinder *(*)(const char *);
    auto check =
        reinterpret_cast<CheckService>(dlsym(RTLD_DEFAULT, "AServiceManager_checkService"));
    return ndk::SpAIBinder(check ? check("dnsresolver") : nullptr);
}
bool valid_id(uint32_t id) {
    return id > 0 && id <= INT32_MAX;
}
} // namespace

extern "C" __attribute__((visibility("default"))) int ae_resolver_read_config(uint32_t id,
                                                                              AeDnsConfig *output) {
    if (!output || !valid_id(id))
        return -EINVAL;
    auto binder = service();
    if (!binder.get())
        return -ENOTCONN;
    // Always use the generated proxy. Do not cast a local platform C++ service
    // object into our NDK C++ types; all parameters cross the stable Binder API.
    auto proxy = ndk::SharedRefBase::make<BpDnsResolver>(binder);
    std::vector<std::string> servers, domains, tls;
    // AIDL out arrays carry the caller's requested size. Android 10 writes
    // timeout_count[0] without resizing it; an empty array crashes its service.
    std::vector<int32_t> params, stats, timeouts(1, 0);
    const auto status = proxy->getResolverInfo(
        static_cast<int32_t>(id), &servers, &domains, &tls, &params, &stats, &timeouts);
    const int error = status_error(status);
    if (error)
        return error;
    if (servers.empty())
        return -ENOENT;
    if (!tls.empty())
        return -ENOTSUP; // Private DNS is outside this design.
    std::string prefix;
    const int prefix_error = status_error(proxy->getPrefix64(static_cast<int32_t>(id), &prefix));
    if (!prefix_error)
        return -ENOTSUP; // Do not omit an active DNS64/NAT64 prefix.
    if (prefix_error != -ENOENT)
        return prefix_error;
    if (servers.size() > 8 || domains.size() > 6 || params.size() != 6)
        return -EOVERFLOW;
    AeDnsConfig result{};
    result.server_count = static_cast<uint32_t>(servers.size());
    result.domain_count = static_cast<uint32_t>(domains.size());
    for (size_t i = 0; i < servers.size(); ++i) {
        if (servers[i].empty() || servers[i].size() >= sizeof(result.servers[i]))
            return -EINVAL;
        std::memcpy(result.servers[i], servers[i].c_str(), servers[i].size() + 1);
    }
    for (size_t i = 0; i < domains.size(); ++i) {
        if (domains[i].size() >= sizeof(result.domains[i]))
            return -EOVERFLOW;
        std::memcpy(result.domains[i], domains[i].c_str(), domains[i].size() + 1);
    }
    for (size_t i = 0; i < params.size(); ++i)
        result.parameters[i] = params[i];
    *output = result;
    return 0;
}

extern "C" __attribute__((visibility("default"))) int ae_resolver_reserve(uint32_t id) {
    if (!valid_id(id))
        return -EINVAL;
    auto binder = service();
    if (!binder.get())
        return -ENOTCONN;
    auto proxy = ndk::SharedRefBase::make<BpDnsResolver>(binder);
    return status_error(proxy->createNetworkCache(static_cast<int32_t>(id)));
}

extern "C" __attribute__((visibility("default"))) int
ae_resolver_configure(uint32_t id, const AeDnsConfig *config) {
    if (!config || !valid_id(id) || !config->server_count || config->server_count > 8 ||
        config->domain_count > 6)
        return -EINVAL;
    ResolverParamsParcel params;
    params.netId = static_cast<int32_t>(id);
    params.sampleValiditySeconds = config->parameters[0];
    params.successThreshold = config->parameters[1];
    params.minSamples = config->parameters[2];
    params.maxSamples = config->parameters[3];
    params.baseTimeoutMsec = config->parameters[4];
    params.retryCount = config->parameters[5];
    for (uint32_t i = 0; i < config->server_count; ++i) {
        const size_t length = strnlen(config->servers[i], sizeof(config->servers[i]));
        if (!length || length == sizeof(config->servers[i]))
            return -EINVAL;
        params.servers.emplace_back(config->servers[i], length);
    }
    for (uint32_t i = 0; i < config->domain_count; ++i) {
        const size_t length = strnlen(config->domains[i], sizeof(config->domains[i]));
        if (length == sizeof(config->domains[i]))
            return -EINVAL;
        params.domains.emplace_back(config->domains[i], length);
    }
    auto binder = service();
    if (!binder.get())
        return -ENOTCONN;
    auto proxy = ndk::SharedRefBase::make<BpDnsResolver>(binder);
    return status_error(proxy->setResolverConfiguration(params));
}

extern "C" __attribute__((visibility("default"))) int ae_resolver_destroy(uint32_t id) {
    if (!valid_id(id))
        return -EINVAL;
    auto binder = service();
    if (!binder.get())
        return -ENOTCONN;
    auto proxy = ndk::SharedRefBase::make<BpDnsResolver>(binder);
    return status_error(proxy->destroyNetworkCache(static_cast<int32_t>(id)));
}
