# AsteriskEnhance

AsteriskEnhance is an optional Zygisk Next module for AsteriskNG, AsteriskBOX,
and AsteriskMETA. It hooks only `/system/bin/netd`, uses the original full
Android UID of system DNS requests to steer TCP/UDP 53 by application policy,
and isolates resolver caches between DNS policies.

DNS sockets remain owned by netd. Routing uses marks derived from the requesting
application UID and reuses the core's existing transparent proxy or SOCKS ingress.
The module does not add a dedicated DNS listener. `asteriskd` publishes the policy;
disconnect or lease expiration withdraws it, and a previous active session is
never restored.

## Compatibility

- Android 8 / API 26 or newer, with Zygisk Next installed and enabled.
- TPROXY and TUN2SOCKS integration starts at API 26; BPF2SOCKS starts at API 33.
- TUN and the core's eBPF mode remain managed by the core.
- arm64-v8a, armeabi-v7a, x86_64, and x86 use the same runtime capability checks.
- Activation requires the expected netd/resolver symbols, successful hooks,
  a usable resolver backend, and query lifetime tracking. There is no device
  build ID allowlist or restriction based on which architectures were tested.
- Compatible API 33+ systems can advertise all three modes. Earlier systems
  advertise TPROXY/TUN2SOCKS. The supervisor and helper determine BPF
  attachment compatibility at runtime; enhancement does not exclude newer APIs
  solely by their Android version.

Runtime verification includes x86_64 AVDs and an ARM64 Android 16 device with
SELinux enforcing. Other ABI builds remain available without an artificial
runtime block; device compatibility feedback is welcome.

Activation requires a valid prepared resolver configuration. Caches belong to individual networks
and policy generations. Active Private DNS, DNS64/NAT64, or unknown resolver
configuration prevents activation when a safe clone cannot be made.

Network discovery omits caches without DNS servers, while cache
reservation still treats those entries as occupied. A newly configured network
changes the discovered inventory and requires a new policy generation. INFO
reports module capabilities; it does not guarantee that the system has published
DNS configuration. PREPARE fails when no configured DNS network is available.
Resolver preparation failures are logged under the `AsteriskEnhance` logcat tag.

## Missed netd injection recovery

The installer selects `post-mount.sh` for KernelSU and APatch, after their
module `post-fs-data.sh` scripts have finished. Magisk uses `post-fs-data.sh`;
its module order does not guarantee that Zygisk Next has already initialized.
Both use the same synchronous recovery script. An upgrade removes the old
`service.sh` and installs only the selected entry point.

Recovery runs only before Zygote has ever started and before boot completion.
It requires an enabled Zygisk Next module, a responding daemon, readable and
unchanged process identities, and netd starting before that daemon. If the
module loaded marker and library are both absent, it stops netd, waits up to
five seconds for init to confirm it stopped, then starts it again. Separate
stop/start avoids netd's `onrestart` actions. A stop timeout never sends start
while the old process may still be stopping. Control failures and outcomes are
logged under `AsteriskEnhance` with `netd_recovery` and the selected boot stage.

A process-lifetime abstract socket marks module loading before hook installation.
Hook, capability, and DNS preparation failures therefore do not trigger this
recovery. The DNS companion initializes after boot completion and is not checked
in this early stage. Missing/disabled or unready Zygisk Next, unknown process
state, a changed process, a module already loaded, or a framework that has
started skips recovery. A `/dev` lock limits the check to once per boot. There
is no background worker, late-boot fallback, or retry; recovery runs independently
of the applications and their VPN lifecycle.

## SELinux policy

The module installs `sepolicy.rule` in standalone packages and application APKs.
It grants `netd` only the additional `self:process execmem` permission required
by Zygisk Next inline hooks. SELinux remains enforcing. Before installing hooks,
the module checks executable memory access and leaves enhancement unavailable
if this prerequisite fails, rather than risking a netd crash.

The companion runs in the ROOT manager's domain. Zygisk Next supplies its
private transport; the companion passes the resolver bridge as a file descriptor
with the `system_lib_file` label. Resolver Binder access uses netd's existing
platform permissions. No application-domain access, permissive domain, or
wildcard SELinux grant is added by this module.

## Standalone build

Python 3.10 or newer, Android SDK Build Tools 37.0.0, and an Android NDK are
required. The build entry point selects the Windows, Linux, or macOS toolchain
using the [NDK host layout](https://developer.android.com/ndk/guides/other_build_systems)
and inherits the caller's environment.

```sh
python tools/build.py --sdk "<SDK_DIR>" --ndk "<NDK_DIR>"
```

The default build includes arm64-v8a, armeabi-v7a, x86_64, and x86, and writes
`dist/asterisk-enhance.zip`. Use `--abi x86_64` for one ABI or `--abis` for an
explicit list. `--work-directory` selects the intermediate directory, and
`--output-directory` exports each ABI's native libraries and runtime identity.
Application builds use `--skip-package` to build and export payloads without
creating a separate module ZIP.

## Application integration and installation

The Git submodule checkout path is `enhance/src/main/module`. Local
application builds can use `-PenhanceSourceDir=<path>`. Each application's
`enhance` Gradle module adds installer files and all four ABI payloads before
APK signing. Payloads live under `assets/enhance/lib/<ABI>/` and are independent
of the APK's JNI ABI split.

The module ID is `zygisk-next-asterisk-enhance`; ROOT managers display
`Asterisk Enhance`. The installer extracts only module files and does not bundle
Zygisk Next.

Applications pass their own installed APK directly to the Magisk, KernelSU, or
APatch CLI and display live installation output. If a ROOT manager does not
accept APK files, export the application APK, rename its extension to `.zip`,
and install it manually. Installation and updates require a device reboot;
the applications never reboot automatically.

## Control interface

`@asterisk.enhance.dns` provides control requests and a read-only INFO query.
Control requests require the root process owning the current
`@asteriskd.control` listener. INFO does not establish a control session or
change DNS policy or caches.

Applications offer an update only when the running `versionCode` is lower than
the version bundled in their APK. `version` and `buildId` are diagnostic fields.
Increment `versionCode` in `module/module.prop` for releases requiring an update.
Detection and update decisions do not inspect module directories on disk.

See [control-protocol.md](docs/control-protocol.md) for framing, cache ownership,
and lifecycle requirements.

Idle control workers wait for events. Policies last until explicit withdrawal or
control-connection loss, with no heartbeat or periodic renewal. Resolver changes
trigger configuration checks and fresh cache generations when needed. A stalled
supervisor with an open connection retains its last policy. Capability revision 5
requires matching application support.

## License

The project uses [GPL-3.0](LICENSE). Interface definitions and headers under
`third_party/` retain their original licenses and provenance notes.
