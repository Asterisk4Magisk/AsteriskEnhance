# Binder NDK C++ helpers

Unmodified Apache-2.0 headers from Android 16:

https://android.googlesource.com/platform/frameworks/native/+/refs/tags/android-16.0.0_r1/libs/binder/ndk/include_cpp/android/

Used with the SDK AIDL compiler to build the API 29+ bridge. The module itself remains API 26 and does not link libbinder_ndk. Platform-only service-manager lookup is resolved through its documented C signature; generated resolver transactions use the stable NDK Binder API.
