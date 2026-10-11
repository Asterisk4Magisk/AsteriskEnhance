# AOSP Android 8.1 resolver ABI header

Unmodified Apache-2.0 header from `android-8.1.0_r1`:

https://android.googlesource.com/platform/system/netd/+/android-8.1.0_r1/server/ResolverController.h

Used by the exact-profile API27 platform bridge to detect a validated experimental DNS-over-TLS provider. Its accessor reads the synchronized process-global provider table. Namespace remapping keeps this historical declaration distinct from API28; no C++ container crosses the C bridge.
