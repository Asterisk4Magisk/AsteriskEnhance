# AOSP Android 9 resolver ABI headers

Unmodified Apache-2.0 headers from the `android-9.0.0_r1` tag:

- https://android.googlesource.com/platform/system/netd/+/android-9.0.0_r1/server/ResolverController.h
- https://android.googlesource.com/platform/system/netd/+/android-9.0.0_r1/server/dns/DnsTlsServer.h

Used only by the platform-namespace C bridge to read Private DNS status for the exact tested API 28 netd ELF profile. No platform C++ containers cross the bridge. The controller accessor reads a synchronized process-global configuration; its class contains no instance state beyond its vtable. Other platform profiles cannot use this ABI.
