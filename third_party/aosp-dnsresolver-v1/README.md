# Android DNS Resolver stable AIDL v1

IDnsResolver and ResolverParamsParcel come from the frozen v1 API in:

https://android.googlesource.com/platform/packages/modules/DnsResolver/+/refs/tags/android-13.0.0_r1/aidl_api/dnsresolver_aidl_interface/1/android/net/

INetdEventListener comes from its frozen v1 platform interface:

https://android.googlesource.com/platform/frameworks/libs/net/+/refs/tags/android-13.0.0_r1/common/netd/aidl_api/netd_event_listener_interface/1/android/net/metrics/INetdEventListener.aidl

The Android AIDL compiler generates NDK transaction code from these definitions. No handwritten transaction numbers. Only existing stable resolver methods are used; listeners are not registered by the module. The modern Binder bridge is built for API 29+ and must not become a load-time dependency of the API 26 module.
