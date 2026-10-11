# Control protocol v1

The companion owns `@asterisk.enhance.dns`. Control requests require a root peer whose kernel `SO_PEERCRED` PID matches the current `@asteriskd.control` listener. It checks this both before and after reading a complete request. Owning root alone is insufficient for control. The companion supplies a separate, random connection cookie on its private Zygisk Next channel; public clients cannot select that cookie. The separate read-only INFO request accepts root peers without a supervisor or control ownership.

All integers below are unsigned little endian. Frames have an exact 40-byte header:

| Offset | Size | Field |
| --- | --- | --- |
| 0 | 4 | Magic `0x314e4541` (`AEN1`) |
| 4 | 2 | Protocol version, 1 |
| 6 | 2 | Opcode |
| 8 | 4 | Body length, at most 1 MiB |
| 12 | 4 | Nonzero request ID, strictly increasing within a connection |
| 16 | 8 | Supervisor instance ID |
| 24 | 8 | Service cycle ID |
| 32 | 8 | Policy generation |

Clients first send HELLO (1) with a nonzero supervisor instance. PREPARE (2), ACTIVATE (3), RENEW (4), DEACTIVATE (5), RELEASE (6) require all three identities. PREPARE carries policy data; ACTIVATE and RENEW each carry an exact eight-byte absolute CLOCK_BOOTTIME expiry. HELLO, DEACTIVATE and RELEASE are bodyless. Unknown versions/opcodes, oversized/truncated frames and invalid body sizes close the transport. Semantically invalid requests return ERROR (8). Successful state changes return ACK (7); HELLO returns CAPABILITIES (9). Every response echoes the exact request identity.

## Bodies

INFO (10) is bodyless and requires zero supervisor/cycle/generation identities and a nonzero request ID. INFO_REPLY (11) echoes the request ID, keeps those identities zero, and carries at most 512 bytes of ASCII text: `AE_INFO 1` followed by exact newline-terminated `versionCode`, `version`, `buildId`, `netd`, `api`, `modes`, `flags`, and `protocol` fields. `protocol` is the capability revision (4), separate from the frame protocol (1). The version and deterministic per-ABI build identifier are compiled into the library loaded in netd. The companion receives the immutable snapshot over its private channel; it does not read module files to report it.

INFO is a one-shot query. It never enters the control actor, sends HELLO, claims the control client, creates caches, changes a generation, or renews a lease. The broker bounds first-frame concurrency and deadlines and sends this small response without waiting for a slow reader. `asteriskd enhancement-info` exposes this query without starting the supervisor or initializing its configuration, telemetry or network resources. Applications offer an update only when the running versionCode is lower than the version bundled in their own APK. Equal or newer versions still require runtime capability checks; version text and buildId are diagnostic fields and do not trigger an update. Unavailable/older endpoints allow installation. Manager CLI installation success yields a process-local versionCode reboot prompt without inspecting disk state.

CAPABILITIES is 48 bytes: the netd instance as `u64`, followed by ten `u32`: capability revision (4), platform API, supported mode bitmap, mark mask, proxy mark, direct mark, consumer version (2), lease milliseconds, renewal milliseconds, flags. The frame protocol remains version 1. Mode bits 0/1/2 mean TPROXY/TUN2SOCKS/BPF2SOCKS. Flag bit 0 is reserved and unsupported. Flag bit 1 means native original-network discovery; bit 2 means original DNS route export. Production clients require revision 4 and both facilities, and reject the reserved flag. Capabilities depend on resolved netd/resolver interfaces and ready hooks/backend/query tracking for every ABI: compatible API 33+ systems advertise bits 0–2, earlier systems advertise bits 0–1. BPF attachment compatibility is evaluated by the supervisor and helper at runtime. Missing interfaces or failed initialization advertise zero modes; there is no architecture or build ID allowlist. Capability negotiation does not bypass the consumer's actual route-readiness checks or BPF attachment compatibility checks.

PREPARE begins with ten `u32`: run mode (1/2/3), list mode (whitelist 1 / blacklist 2 / global 3), consumer version (2), existing entry port, mark mask, proxy mark, direct mark, UID count, forced-bypass UID count, original-network count. A separate `u64` netd instance follows at offset 40. Arrays start at offset 48 in that order. Lists are sorted, unique and contain full Android UIDs; limits are 8192 + 8192 UIDs and 64 real network IDs (1–65535). The exact length is required; trailing data is rejected. Consumer 1 is rejected before allocation; the active consumer version is 2.

A zero original-network count requests native discovery. The actor obtains a bounded sorted inventory from its validated platform backend before allocating caches; an empty or invalid inventory fails preparation. It checks inventory changes on activation and renewal as well as comparing DNS settings. A changed network set withdraws the old generation and returns CACHE_ERROR; clients must prepare a new generation. Nonempty network lists explicitly select original networks. Boot startup never depends on an app process or persisted network IDs.

The current profile contract uses mask `0x61000000`, proxy mark `0x21000000`, and direct mark `0x41000000`. The module supplies the final proxy routing mark before socket routing. TPROXY/TUN2SOCKS OUTPUT only exits the ordinary classifier for marked DNS; BPF2SOCKS consumes the mark directly. Enhanced IPv4 TPROXY requires preferred source `127.0.0.1` on its existing local default route. Core GID and forced bypass UIDs take precedence. Original network fwmark fields remain intact. The logical cache ID never replaces the real network ID in the socket mark.

ACK/ERROR bodies are 24 bytes: netd instance `u64`, then result code, phase, retained cache count and reserved zero (`u32` each). Results: OK 0, INVALID 1, UNSUPPORTED 2, STALE 3, BUSY 4, CACHE_ERROR 5, DRAINING 6, EXHAUSTED 7, IO_ERROR 8. Phases: IDLE 0, PREPARED 1, ACTIVE 2, DRAINING 3.

The successful consumer-2 PREPARE ACK appends a `u32` route count and 1–64 exact 32-byte records: original network ID, original DNS mark, address family (4/6), IPv6 scope ID (`u32` each), then 16 address bytes in network byte order. IPv4 uses the first four bytes with zero padding and zero scope. The mark comes from the verified original NetworkController function for UID 0 on that network; addresses come from the original configuration copied into the reserved cache. Missing, changed, malformed or oversized route inventories fail preparation and roll back owned caches. The maximum response is 2116 bytes including its header.

Before ACTIVATE, the daemon verifies module capabilities, consumer readiness, installed rules, and cache preparation. Startup and resume do not send synthetic DNS queries or inject reserved answers into core configurations.

## Lifetime and deadlines

ACTIVATE/RENEW carry the client's absolute CLOCK_BOOTTIME expiry (`enqueue time + 2000 ms`). The private channel also carries the broker's framing deadline; the session uses the earlier expiry. A delayed broker read cannot renew the client's budget. The netd writer rechecks after acquiring its gate; activation/renewal also checks after potentially blocking resolver-configuration calls and before publication. Late responses cannot be mistaken for a later request: a failed private exchange closes that channel. Native teardown waits until the last possible publication expiry plus the full lease if acknowledged withdrawal is unavailable.

ACTIVATE starts a 3000 ms lease; renew every 1000 ms. Query readers independently enforce BOOTTIME expiration, even if the background writer is blocked. RENEW cannot activate a prepared or expired generation. PREPARE retains ownership immediately after reservation, including when later configuration or rollback fails.

DEACTIVATE withdraws the snapshot and acknowledges withdrawal. RELEASE waits for both snapshot readers and their accepted resolver workers before deleting caches. A failed deletion remains owned for retry. Disconnect or lease expiration withdraws and automatically reaps when quiescent. Private-channel reconnect preserves the actor's retained resources but does not restore its previous active policy. A new generation uses fresh logical IDs; an old request cannot reactivate it.
