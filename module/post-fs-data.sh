#!/system/bin/sh
# Copyright 2026, Asterisk4Magisk contributors
# SPDX-License-Identifier: GPL-3.0

MODDIR=${0%/*}
AE_STAGE=${0##*/}
AE_STAGE=${AE_STAGE%.sh}

ae_log() {
    log -p i -t AsteriskEnhance "netd_recovery stage=$AE_STAGE $*"
}
ae_lock() {
    # /dev is recreated at boot. Never retry a recovery in this boot.
    mkdir /dev/.asterisk-enhance-netd-recovery 2>/dev/null
}
ae_enabled() {
    [ ! -e "$MODDIR/disable" ] && [ ! -e "$MODDIR/remove" ] &&
        [ -d /data/adb/modules/zygisksu ] &&
        [ ! -e /data/adb/modules/zygisksu/disable ] &&
        [ ! -e /data/adb/modules/zygisksu/remove ]
}
ae_early_window() {
    ae_boot=$(getprop sys.boot_completed) || return 1
    case "$ae_boot" in ''|0) ;; *) return 1 ;; esac
    for ae_service in zygote zygote_secondary; do
        ae_state=$(getprop "init.svc.$ae_service") || return 1
        case "$ae_state" in ''|stopped) ;; *) return 1 ;; esac
        ae_started=$(getprop "ro.boottime.$ae_service") || return 1
        [ -z "$ae_started" ] || return 1
    done
    if ae_framework=$(pidof zygote64 zygote system_server 2>/dev/null); then
        [ -z "$ae_framework" ]
    else
        [ "$?" -eq 1 ]
    fi
}
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
ae_zn_ready() {
    ae_loader=$(readlink "/proc/$1/exe") || return 1
    ae_status=$(timeout 1 "$ae_loader" status 2>/dev/null) || return 1
    # version_local is available offline; version is returned by the live daemon.
    # inject_state describes the Zygote monitor, not readiness of the init hook.
    printf '%s\n' "$ae_status" | grep -q '^version:'
}
ae_start_time() {
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
    if grep -q " @$1\$" /proc/net/unix; then return 0
    else return "$?"; fi
}
ae_loaded() {
    # The marker is published before hooks; hook failures must not cause restarts.
    if ae_socket_present "asterisk.enhance.netd.$1"; then return 0
    else [ "$?" -eq 1 ] || return 2; fi
    [ -r "/proc/$1/maps" ] || return 2
    if grep -q 'libasterisk_enhance' "/proc/$1/maps" 2>/dev/null; then return 0
    else return "$?"; fi
}
ae_absent() {
    if ae_loaded "$1"; then return 1
    else [ "$?" -eq 1 ]; fi
}
ae_wait_netd() {
    ae_wait=0
    while [ "$ae_wait" -lt "${2:-10}" ]; do
        [ "$(getprop init.svc.netd)" = "$1" ] && return 0
        sleep 0.1
        ae_wait=$((ae_wait + 1))
    done
    [ "$(getprop init.svc.netd)" = "$1" ]
}
ae_recover_netd() {
    ae_lock || { ae_log 'result=skipped reason=already_checked_this_boot'; return 0; }
    ae_enabled || { ae_log 'result=skipped reason=module_disabled'; return 0; }
    ae_early_window || { ae_log 'result=skipped reason=framework_started_or_state_unknown'; return 0; }
    command -v timeout >/dev/null 2>&1 || { ae_log 'result=skipped reason=timeout_unavailable'; return 0; }
    ae_netd=$(ae_netd_pid) || { ae_log 'result=skipped reason=netd_unavailable'; return 0; }
    ae_absent "$ae_netd" || { ae_log 'result=skipped reason=module_present_or_state_unknown'; return 0; }
    ae_zn=$(ae_zn_pid) || { ae_log 'result=skipped reason=zn_unavailable'; return 0; }
    # Do not wait for another module's post-fs-data script: it may run after ours.
    ae_zn_ready "$ae_zn" || { ae_log 'result=skipped reason=zn_not_ready'; return 0; }
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
    if ! ae_enabled || ! ae_early_window ||
        [ "$(ae_netd_pid)" != "$ae_netd" ] || [ "$(ae_zn_pid)" != "$ae_zn" ] ||
        [ "$(ae_start_time "$ae_netd")" != "$ae_netd_start" ] ||
        [ "$(ae_start_time "$ae_zn")" != "$ae_zn_start" ] || ! ae_absent "$ae_netd"; then
        ae_log 'result=skipped reason=process_or_module_or_boot_stage_changed'
        return 0
    fi
    # Control messages are handled by init during exec waits. Use stop/start to
    # avoid netd's onrestart actions, which can start Zygote even in early boot.
    ae_log "action=stop_start reason=netd_predates_zn netd_pid=$ae_netd zn_pid=$ae_zn"
    ae_error=$(timeout 1 setprop ctl.stop netd 2>&1)
    ae_code=$?
    [ "$ae_code" -eq 0 ] || ae_log "result=failed op=stop code=$ae_code reason=$ae_error"
    if ! ae_wait_netd stopped 50; then
        ae_log 'result=failed op=stop reason=stop_timeout retry=none'
        return 0
    fi
    # Starting while the old process is stopping re-enables automatic restart
    # and onrestart actions. Start only after init has confirmed it stopped.
    ae_error=$(timeout 1 setprop ctl.start netd 2>&1)
    ae_code=$?
    if [ "$ae_code" -ne 0 ]; then
        ae_log "result=failed op=start code=$ae_code reason=$ae_error retry=none"
        return 0
    fi
    if ! ae_wait_netd running; then
        ae_log 'result=failed op=start reason=start_timeout retry=none'
        return 0
    fi
    ae_wait=0
    while [ "$ae_wait" -lt 10 ]; do
        ae_new_netd=$(ae_netd_pid)
        if [ -n "$ae_new_netd" ] && [ "$ae_new_netd" != "$ae_netd" ] && ae_loaded "$ae_new_netd"; then
            # The DNS companion initializes after boot_completed, not here.
            ae_log "result=recovered netd_pid=$ae_new_netd"
            return 0
        fi
        sleep 0.1
        ae_wait=$((ae_wait + 1))
    done
    ae_log 'result=failed reason=module_not_loaded_after_start retry=none'
}

ae_recover_netd
