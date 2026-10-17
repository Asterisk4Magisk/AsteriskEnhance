# AOSP Android 9 resolver ABI headers

Unmodified Apache-2.0 headers from the `android-9.0.0_r1` tag:

- https://android.googlesource.com/platform/system/netd/+/android-9.0.0_r1/server/ResolverController.h
- https://android.googlesource.com/platform/system/netd/+/android-9.0.0_r1/server/dns/DnsTlsServer.h

Used by the platform-namespace C bridge to read Private DNS status on API28 through the expected AOSP interface. The backend resolves the accessor at runtime; it does not use a device build-ID or tested-ELF allowlist. Compatibility still depends on the expected ABI: vendor changes may be incompatible even when the symbol is present. No platform C++ containers cross the bridge. The expected controller accessor reads a synchronized process-global configuration; its class contains no instance state beyond its vtable.
