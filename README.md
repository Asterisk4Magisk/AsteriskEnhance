# AsteriskEnhance

AsteriskEnhance is an optional Zygisk Next module for AsteriskNG, AsteriskBOX,
and AsteriskMETA. It hooks only `/system/bin/netd`, uses the original full
Android UID of system DNS requests to steer TCP/UDP 53 by application policy,
and isolates resolver caches between DNS policies.

- DNS sockets remain owned by netd. Routing uses marks derived from the
  requesting application UID and reuses the core's existing transparent proxy
  or SOCKS ingress. The module adds no dedicated DNS listener.
- `asteriskd` publishes the policy. Explicit withdrawal or loss of the control
  connection withdraws it. There is no periodic renewal or policy expiration,
  and a previous active session is never restored.

## Requirements

| Item | Requirement |
| --- | --- |
| Android | 8.0 / API 26 or newer |
| Framework | Zygisk Next installed and enabled |
| ABIs | arm64-v8a, armeabi-v7a, x86_64, x86 (same runtime checks for all) |
| Modes | TPROXY and TUN2SOCKS from API 26; BPF2SOCKS from API 33 |
| SELinux | Enforcing; see [SELinux policy](#selinux-policy) |

TUN and the core's eBPF mode remain managed by the core.

Activation requires the expected netd/resolver symbols, successful hooks, a
usable resolver backend, and query lifetime tracking. There is no device build
ID allowlist and no restriction based on which architectures were tested.
Compatible API 33+ systems advertise all three modes; earlier systems advertise
TPROXY and TUN2SOCKS. The supervisor and helper decide BPF attachment
compatibility at runtime; newer APIs are never excluded by version alone.

Runtime verification includes x86_64 AVDs and an ARM64 Android 16 device with
SELinux enforcing. Other ABI builds remain available without an artificial
runtime block; device compatibility feedback is welcome.

## DNS behavior

- Caches belong to individual networks and policy generations. Activation
  requires a valid prepared resolver configuration.
- Active Private DNS, DNS64/NAT64, or an unknown resolver configuration prevents
  activation when a safe clone cannot be made.
- Networks without DNS servers are omitted from discovery but still count as
  occupied cache IDs. A newly configured network changes the inventory and
  requires a new policy generation.
- With no usable network (offline), preparation still succeeds. Activation
  installs a zero-cache UID guard and reports `waiting-network` until a network
  change prepares a fresh generation. Selected queries never fall back to the
  original shared cache while waiting.
- Discovery errors and invalid or unsafe resolver configurations fail
  preparation. INFO reports module capabilities only; it does not guarantee
  that the system has published a DNS configuration.

## Troubleshooting

All runtime messages use the `AsteriskEnhance` logcat tag.

| Symptom | Where to look |
| --- | --- |
| Enhancement never becomes active | `loaded; API …; context hook=…` after boot. `context hook=0` means a missing interface or hook failure. |
| `hook executable memory unavailable` | The module SELinux rule was not loaded; check that the ROOT manager applied `sepolicy.rule`. |
| Preparation fails | `DNS prepare failure: stage=… reason=… error=… network=…`. The supervisor receives the same stage, reason, error and network ID, and keeps them after logcat rotates. |
| Module missing after boot | `netd_recovery stage=…` lines; see [Missed netd injection recovery](#missed-netd-injection-recovery). |

Only known transient preparation failures with complete cleanup receive bounded
startup retries. Stage and reason codes are listed in the
[control protocol](docs/control-protocol.md#failure-details).

## Installation

The module ID is `zygisk-next-asterisk-enhance`; ROOT managers display
`Asterisk Enhance`. The installer extracts only module files and does not
bundle Zygisk Next.

Applications pass their own installed APK directly to the Magisk, KernelSU, or
APatch CLI and display the live installation output. If a ROOT manager does not
accept APK files, export the application APK, rename its extension to `.zip`,
and install it manually. Installation and updates require a device reboot; the
applications never reboot automatically.

Applications offer an update only when the running `versionCode` is lower than
the version bundled in their APK. `version` and `buildId` are diagnostic fields.
Increment `versionCode` in `module/module.prop` for releases that require an
update. Update decisions never inspect module directories on disk.

## Missed netd injection recovery

The installer selects `post-mount.sh` for KernelSU and APatch, which runs after
their module `post-fs-data.sh` scripts finish. Magisk uses `post-fs-data.sh`;
its module order does not guarantee that Zygisk Next has already initialized.
Both use the same synchronous recovery script. An upgrade removes the old
`service.sh` and installs only the selected entry point.

Recovery runs only before Zygote has ever started and before boot completion.
It requires:

- an enabled Zygisk Next module with a responding daemon;
- readable and unchanged process identities;
- netd started before that daemon;
- neither the module loaded marker nor the library present in netd.

It then stops netd, waits up to five seconds for init to confirm the stop, and
starts it again. Separate stop/start avoids netd's `onrestart` actions, and a
stop timeout never sends start while the old process may still be stopping.
Control failures and outcomes are logged with `netd_recovery` and the boot stage.

A process-lifetime abstract socket marks module loading before hook
installation, so hook, capability, and DNS preparation failures never trigger
recovery. The DNS companion initializes after boot completion and is not checked
in this early stage. Recovery is skipped when Zygisk Next is missing, disabled
or unready, when the process state is unknown or changed, when the module is
already loaded, or when the framework has started. A `/dev` lock limits the
check to once per boot. There is no background worker, late-boot fallback, or
retry; recovery is independent of the applications and their VPN lifecycle.

## SELinux policy

The module installs `sepolicy.rule` in standalone packages and application
APKs. It grants `netd` only the additional `self:process execmem` permission
required by Zygisk Next inline hooks. Before installing hooks the module checks
executable memory access and leaves enhancement unavailable if this check
fails, rather than risking a netd crash.

The companion runs in the ROOT manager's domain. Zygisk Next supplies its
private transport, and the companion passes the resolver bridge to netd as a
file descriptor with the `system_lib_file` label. Resolver Binder access uses
netd's existing platform permissions. The module adds no application-domain
access, permissive domain, or wildcard SELinux grant.

## Runtime cost

- No periodic timers or polling. Idle broker and netd workers wait for socket,
  property, or eventfd events; resolver hooks only signal an eventfd.
- Policy decisions on the DNS path do no allocation, file access, IPC, or
  full-list scan (binary search over sorted UID lists).
- API 26–28 discovery reads only networks that the resolver configure/delete
  hooks have seen. The full netId range is probed once, when the backend starts.
- API 27 checks its TLS validation state only for queries that the policy
  selects, because that platform has no completion callback.

## Control interface

`@asterisk.enhance.dns` provides control requests and a read-only INFO query.
Control requests require the root process that owns the current
`@asteriskd.control` listener. INFO never establishes a control session or
changes DNS policy or caches, and it is answered even while a control request
is in progress.

Policies last until explicit withdrawal or control-connection loss. Resolver
changes trigger configuration checks and fresh cache generations when needed.
A stalled supervisor with an open connection retains its last policy.
Capability revision 7 requires matching application support.

See [control-protocol.md](docs/control-protocol.md) for framing, cache
ownership, and lifecycle requirements.

## Building

Python 3.10 or newer, Android SDK Build Tools 37.0.0, and an Android NDK are
required. The build entry point selects the Windows, Linux, or macOS toolchain
using the [NDK host layout](https://developer.android.com/ndk/guides/other_build_systems)
and inherits the caller's environment.

```sh
python tools/build.py --sdk "<SDK_DIR>" --ndk "<NDK_DIR>"
```

- The default build includes all four ABIs and writes
  `dist/asterisk-enhance.zip`. Use `--abi x86_64` for one ABI or `--abis` for
  an explicit list.
- `--work-directory` selects the intermediate directory; `--output-directory`
  exports each ABI's native libraries and runtime identity.
- Application builds use `--skip-package` to build and export payloads without
  creating a separate module ZIP.

### Application integration

The Git submodule checkout path is `enhance/src/main/module`. Local application
builds can use `-PenhanceSourceDir=<path>`. Each application's `enhance` Gradle
module adds the installer files and all four ABI payloads before APK signing.
Payloads live under `assets/enhance/lib/<ABI>/` and are independent of the
APK's JNI ABI split.

## License

The project uses [GPL-3.0](LICENSE). Interface definitions and headers under
`third_party/` retain their original licenses and provenance notes.
