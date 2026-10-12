# Copyright 2026, Asterisk4Magisk contributors
# SPDX-License-Identifier: GPL-3.0

SKIPUNZIP=1
case "$ARCH" in
    x64)
        ABI=x86_64
        ;;
    arm64)
        ABI=arm64-v8a
        ;;
    arm)
        ABI=armeabi-v7a
        ;;
    x86)
        ABI=x86
        ;;
    *)
        abort "Unsupported architecture: $ARCH"
        ;;
esac
[ "$API" -ge 26 ] || abort "Android 8 or newer is required"
[ -d /data/adb/modules/zygisksu ] || abort "Install Zygisk Next before AsteriskEnhance"
mkdir -p "$MODPATH/lib"
unzip -oj "$ZIPFILE" module.prop zn_modules.txt sepolicy.rule post-fs-data.sh -d "$MODPATH" >&2
[ -f "$MODPATH/sepolicy.rule" ] || abort "SELinux policy is missing"
[ -f "$MODPATH/post-fs-data.sh" ] || abort "Early boot recovery script is missing"
# KernelSU and APatch run post-mount after every module's post-fs-data script.
BOOT_SCRIPT=post-fs-data.sh
if [ "$KSU" = true ] || [ "$APATCH" = true ]; then
    BOOT_SCRIPT=post-mount.sh
fi
# Keep one entry point and remove the previous late boot recovery on upgrades.
rm -f "$MODPATH/service.sh" "$MODPATH/post-mount.sh"
if [ "$BOOT_SCRIPT" = post-mount.sh ]; then
    mv "$MODPATH/post-fs-data.sh" "$MODPATH/post-mount.sh"
fi
PAYLOAD=lib
if unzip -l "$ZIPFILE" 2>/dev/null | grep -q "assets/enhance/lib/"; then
    PAYLOAD=assets/enhance/lib
fi
unzip -oj "$ZIPFILE" \
    "$PAYLOAD/$ABI/libasterisk_enhance.so" \
    "$PAYLOAD/$ABI/libae_resolver29.so" \
    -d "$MODPATH/lib" >&2
[ -f "$MODPATH/lib/libasterisk_enhance.so" ] || abort "Module package does not contain $ABI"
[ -f "$MODPATH/lib/libae_resolver29.so" ] || abort "Resolver bridge is missing for $ABI"
touch "$MODPATH/skip_mount"
set_perm_recursive "$MODPATH" 0 0 0755 0644
set_perm_recursive "$MODPATH/lib" 0 0 0755 0644 u:object_r:system_lib_file:s0
set_perm "$MODPATH/$BOOT_SCRIPT" 0 0 0755

