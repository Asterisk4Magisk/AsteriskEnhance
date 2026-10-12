#!/system/bin/sh
# Copyright 2026, Asterisk4Magisk contributors
# SPDX-License-Identifier: GPL-3.0

MODDIR=${0%/*}

ae_log() {
    log -p i -t AsteriskEnhance "netd_recovery $*"
}
ae_lock() {
    # /dev is recreated at boot. Never remove this lock or retry in this boot.
    mkdir /dev/.asterisk-enhance-netd-recovery 2>/dev/null
}
ae_enabled() {
    [ ! -e "$MODDIR/disable" ] && [ ! -e "$MODDIR/remove" ] &&
        [ -d /data/adb/modules/zygisksu ] &&
        [ ! -e /data/adb/modules/zygisksu/disable ] &&
        [ ! -e /data/adb/modules/zygisksu/remove ]
}
ae_boot_ready() { [ "$(getprop sys.boot_completed)" = 1 ]; }
ae_netd_pid() {
    set -- $(pidof netd)
    [ "$#" -eq 1 ] && echo "$1"
}
ae_zn_pid() {
    for ae_pid in $(pidof zn-daemon); do
        case "$(readlink "/proc/$ae_pid/exe")" in
            /data/adb/modules/zygisksu/bin/zygiskd32|/data/adb/modules/zygisksu/bin/zygiskd64)
                echo "$ae_pid"
                return 0
                ;;
        esac
    done
    return 1
}
ae_start_time() {
    # Strip pid and parenthesized comm before selecting field 22 (starttime).
    ae_stat=$(cat "/proc/$1/stat" 2>/dev/null) || return 1
    ae_fields=${ae_stat##*) }
    [ "$ae_fields" != "$ae_stat" ] || return 1
    set -f
    set -- $ae_fields
    set +f
    [ "$#" -ge 20 ] || return 1
    shift 19
    case "$1" in ''|*[!0-9]*) return 1 ;; esac
    echo "$1"
}
ae_socket_present() {
    [ -r /proc/net/unix ] || return 2
    if grep -q " @$1\$" /proc/net/unix; then
        return 0
    else
        return "$?"
    fi
}
ae_loaded() {
    # Published before hooks/capability checks; a hook failure is not missed injection.
    if ae_socket_present "asterisk.enhance.netd.$1"; then return 0
    else [ "$?" -eq 1 ] || return 2; fi
    [ -r "/proc/$1/maps" ] || return 2
    if grep -q 'libasterisk_enhance' "/proc/$1/maps" 2>/dev/null; then
        return 0
    else
        return "$?"
    fi
}
ae_module_absent() {
    # Only status 1 proves absence. Unreadable state (2) must skip the restart.
    if ae_loaded "$1"; then return 1
    else [ "$?" -eq 1 ] || return 1; fi
    if ae_socket_present asterisk.enhance.dns; then return 1
    else [ "$?" -eq 1 ]; fi
}
ae_restart() { setprop ctl.restart netd; }

ae_recover_netd() {
    ae_lock || { ae_log 'result=skipped reason=already_checked_this_boot'; return 0; }
    ae_enabled || { ae_log 'result=skipped reason=module_disabled'; return 0; }
    ae_wait=0
    while ! ae_boot_ready; do
        if [ "$ae_wait" -ge 120 ]; then
            ae_log 'result=skipped reason=boot_timeout'
            return 0
        fi
        sleep 1
        ae_wait=$((ae_wait + 1))
    done
    ae_wait=0
    while ! ae_zn=$(ae_zn_pid); do
        if [ "$ae_wait" -ge 30 ]; then
            ae_log 'result=skipped reason=zn_unavailable'
            return 0
        fi
        sleep 1
        ae_wait=$((ae_wait + 1))
    done
    ae_netd=$(ae_netd_pid) || { ae_log 'result=skipped reason=netd_unavailable'; return 0; }
    ae_netd_start=$(ae_start_time "$ae_netd") || {
        ae_log 'result=skipped reason=netd_start_unknown'; return 0;
    }
    ae_zn_start=$(ae_start_time "$ae_zn") || {
        ae_log 'result=skipped reason=zn_start_unknown'; return 0;
    }
    if [ "$ae_netd_start" -ge "$ae_zn_start" ]; then
        ae_log 'result=skipped reason=netd_started_after_zn'
        return 0
    fi
    # Give normal module initialization time to publish its loaded marker/companion.
    ae_wait=0
    while [ "$ae_wait" -lt 30 ]; do
        if ! ae_module_absent "$ae_netd"; then
            ae_log "result=skipped reason=module_present_or_state_unknown netd_pid=$ae_netd"
            return 0
        fi
        sleep 1
        ae_wait=$((ae_wait + 1))
    done
    # Revalidate immediately before the one permitted restart.
    if ! ae_enabled || [ "$(ae_netd_pid)" != "$ae_netd" ] ||
        [ "$(ae_zn_pid)" != "$ae_zn" ] ||
        [ "$(ae_start_time "$ae_netd")" != "$ae_netd_start" ] ||
        [ "$(ae_start_time "$ae_zn")" != "$ae_zn_start" ]; then
        ae_log 'result=skipped reason=process_or_module_changed'
        return 0
    fi
    if ! ae_module_absent "$ae_netd"; then
        ae_log 'result=skipped reason=module_present_or_state_unknown'
        return 0
    fi
    ae_log "action=restart reason=netd_predates_zn netd_pid=$ae_netd zn_pid=$ae_zn"
    if ! ae_restart; then
        ae_log 'result=failed reason=restart_command_failed'
        return 0
    fi
    ae_wait=0
    while [ "$ae_wait" -lt 30 ]; do
        ae_new_netd=$(ae_netd_pid)
        if [ -n "$ae_new_netd" ] && [ "$ae_new_netd" != "$ae_netd" ] &&
            ae_loaded "$ae_new_netd" && ae_socket_present asterisk.enhance.dns; then
            ae_log "result=recovered netd_pid=$ae_new_netd"
            return 0
        fi
        sleep 1
        ae_wait=$((ae_wait + 1))
    done
    ae_log 'result=failed reason=companion_not_ready_after_restart retry=none'
}

ae_recover_netd
