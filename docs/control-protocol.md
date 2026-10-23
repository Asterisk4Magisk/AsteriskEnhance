# Control protocol v1

The companion owns the abstract socket `@asterisk.enhance.dns`. This document
is the runtime contract between the module and its supervisor (`asteriskd`).

## Authorization

- **Control requests** require a root peer whose kernel `SO_PEERCRED` PID
  matches the owner of the current `@asteriskd.control` listener. Owning root
  alone is insufficient. The broker checks this when it has read each complete
  request (for HELLO, its header) and before forwarding it. `SO_PEERCRED` is
  fixed when the peer connects, so this confirms that the same peer still owns
  the listener.
- **INFO** accepts any root peer, without a supervisor or control ownership.
- The companion supplies a separate, random connection cookie on its private
  Zygisk Next channel; public clients cannot select it.
- Only one control client is served at a time.

## Framing

All integers are little endian; only the diagnostic error field is signed.
Every frame starts with an exact 40-byte header:

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

Unknown versions/opcodes, oversized/truncated frames and invalid body sizes
close the transport. Semantically invalid requests return ERROR. Every response
echoes the exact request identity.

| Opcode | Name | Direction | Identities | Body |
| --- | --- | --- | --- | --- |
| 1 | HELLO | request | nonzero instance | none |
| 2 | PREPARE | request | all three | policy (see [PREPARE](#prepare)) |
| 3 | ACTIVATE | request | all three | 8-byte expiry |
| 4 | CHECK | request | all three | 8-byte expiry |
| 5 | DEACTIVATE | request | all three | none |
| 6 | RELEASE | request | all three | none |
| 7 | ACK | response | echoed | result (see [Responses](#responses)) |
| 8 | ERROR | response | echoed | result |
| 9 | CAPABILITIES | response to HELLO | echoed | 48 bytes |
| 10 | INFO | request | zero, nonzero request ID | none |
| 11 | INFO_REPLY | response | zero | ≤ 512 bytes of text |
| 12 | NETWORK_CHANGED | event | zero, request ID 1 | none |

Clients send HELLO first. ACTIVATE and CHECK carry an exact eight-byte absolute
`CLOCK_MONOTONIC` expiry.

## Capabilities

CAPABILITIES is 48 bytes: the netd instance as `u64`, then ten `u32`:

1. capability revision (7)
2. platform API
3. supported mode bitmap: bits 0/1/2 are TPROXY/TUN2SOCKS/BPF2SOCKS
4. mark mask
5. proxy mark
6. direct mark
7. consumer version (2)
8. reserved, zero
9. reserved, zero
10. flags

Flags:

| Bit | Meaning |
| --- | --- |
| 0 | Reserved and unsupported; clients reject it |
| 1 | Native original-network discovery |
| 2 | Original DNS route export |
| 3 | Release-progress events (see [Events](#events)) |

Production clients require revision 7 and flag bits 1 and 2. The capability
revision is separate from the frame protocol version, which remains 1. Other
revisions are rejected, not negotiated.

Capabilities depend on resolved netd/resolver interfaces and ready
hooks/backend/query tracking, for every ABI. Compatible API 33+ systems
advertise mode bits 0–2; earlier systems advertise bits 0–1. Missing interfaces
or failed initialization advertise zero modes. There is no architecture or
build ID allowlist. The supervisor and helper evaluate BPF attachment
compatibility at runtime; capability negotiation does not bypass the consumer's
route-readiness or BPF attachment checks.

## INFO

INFO is a one-shot query. It never enters the control actor, sends HELLO,
claims the control client, creates caches, changes a generation, or changes
policy lifetime. The broker answers it with one small nonblocking write, also
while a control request is outstanding, and never waits for a slow reader.

INFO_REPLY echoes the request ID, keeps the identities zero, and carries ASCII
text: `AE_INFO 1` followed by exact newline-terminated `versionCode`, `version`,
`buildId`, `netd`, `api`, `modes`, `flags`, and `protocol` fields. `protocol`
is the capability revision (7). The version and the deterministic per-ABI build
identifier are compiled into the library loaded in netd; the companion receives
this immutable snapshot over its private channel and never reads module files
to report it.

`asteriskd enhancement-info` exposes this query without starting the supervisor
or initializing its configuration, telemetry or network resources.

Update decisions:

- Applications offer an update only when the running `versionCode` is lower
  than the version bundled in their own APK.
- Equal or newer versions still require runtime capability checks; version text
  and `buildId` are diagnostic and never trigger an update.
- Unavailable or older endpoints allow installation. A successful manager CLI
  installation yields a process-local `versionCode` reboot prompt without
  inspecting disk state.

## PREPARE

The body begins with ten `u32`: run mode (1/2/3), list mode (whitelist 1 /
blacklist 2 / global 3), consumer version (2), existing entry port, mark mask,
proxy mark, direct mark, UID count, forced-bypass UID count, original-network
count. A `u64` netd instance follows at offset 40. Arrays start at offset 48 in
that order.

- Lists are sorted, unique, and contain full Android UIDs.
- Limits: 8192 UIDs, 8192 bypass UIDs, and 64 real network IDs (1–65535).
- The exact length is required; trailing data is rejected.
- Consumer 1 is rejected before allocation; the active consumer version is 2.

A zero original-network count requests native discovery: the actor obtains a
bounded sorted inventory from its validated platform backend before allocating
caches, and an invalid inventory fails preparation. A nonempty list explicitly
selects original networks. Boot startup never depends on an application process
or persisted network IDs.

Identity checks (STALE) run before any resolver inventory work. PREPARE retains
ownership immediately after reservation, including when later configuration or
rollback fails.

Isolated cache IDs come from a private range outside real netIds and cycle for
the lifetime of netd. An ID is reused only after its cache was deleted, which
happens only once its queries are quiescent; IDs that are still held elsewhere
are skipped as collisions. EXHAUSTED (7) therefore remains a reserved result.

### Marks

The current profile contract uses mask `0x61000000`, proxy mark `0x21000000`,
and direct mark `0x41000000`.

- The module supplies the final proxy routing mark before socket routing.
- TPROXY/TUN2SOCKS OUTPUT only exits the ordinary classifier for marked DNS;
  BPF2SOCKS consumes the mark directly.
- Enhanced IPv4 TPROXY requires preferred source `127.0.0.1` on its existing
  local default route.
- Core GID and forced-bypass UIDs take precedence.
- Original network fwmark fields remain intact. The logical cache ID never
  replaces the real network ID in the socket mark.

## Responses

ACK and ERROR bodies begin with 24 bytes: netd instance `u64`, then result code,
phase, retained cache count, and reserved zero (`u32` each).

| Result | Code | | Phase | Code |
| --- | --- | --- | --- | --- |
| OK | 0 | | IDLE | 0 |
| INVALID | 1 | | PREPARED | 1 |
| UNSUPPORTED | 2 | | ACTIVE | 2 |
| STALE | 3 | | DRAINING | 3 |
| BUSY | 4 | | | |
| CACHE_ERROR | 5 | | | |
| DRAINING | 6 | | | |
| EXHAUSTED | 7 | | | |
| IO_ERROR | 8 | | | |

### Routes

A successful consumer-2 PREPARE ACK appends a `u32` route count and 0–64 exact
32-byte records: original network ID, original DNS mark, address family (4/6),
IPv6 scope ID (`u32` each), then 16 address bytes in network byte order. IPv4
uses the first four bytes with zero padding and zero scope.

The mark comes from the verified original NetworkController function for UID 0
on that network; addresses come from the original configuration copied into the
reserved cache. Missing, changed, malformed or oversized route inventories fail
preparation and roll back owned caches. The maximum response is 2116 bytes
including its header. An offline PREPARE succeeds with a zero route count
(68-byte frame).

### Failure details

A PREPARE CACHE_ERROR always appends 16 bytes: stage (`u32`), reason (`u32`),
underlying error (`i32`, negative errno where available), and network ID (`u32`,
zero when unavailable). No addresses, domains or UIDs are included. The original
failure is preserved across rollback.

| Stage | Code | | Reason | Code |
| --- | --- | --- | --- | --- |
| unknown | 0 | | unknown | 0 |
| discovery | 1 | | not ready | 1 |
| configuration read | 2 | | original configuration changed | 2 |
| cache reservation | 3 | | private DNS | 3 |
| cache configuration | 4 | | NAT64 | 4 |
| snapshot check | 5 | | invalid configuration | 5 |
| routes | 6 | | backend failure | 6 |
| release | 7 | | capacity | 7 |

## Events

NETWORK_CHANGED (12) is an unsolicited, bodyless event.

- Resolver configuration, cache-deletion and NAT64-prefix hooks signal an
  eventfd without taking the writer lock or making Binder calls. Configuration
  of the module's own isolated caches is ignored.
- The runtime coalesces these signals, and the broker forwards events, including
  those that arrive before a command response. Clients defer CHECK until any
  current operation completes.
- With flag bit 3, the same event is also sent once when a RELEASE that answered
  DRAINING can proceed (the last tracked query ended). Automatic release after
  disconnect uses the same wakeup instead of a timer.
- Own-cache activity does not create recurring checks. Network discovery is
  native and does not require a running application process.
- API 27 has no TLS-validation completion callback. For queries that the policy
  selects, its local resolver state is checked before decoration; unsupported
  state blocks the query using the unavailable cache ID and signals the same
  event. Unselected queries skip this check. The path makes no Binder or network
  requests and adds no idle timer.

## Lifecycle

| Phase | Entered by | Leaves on |
| --- | --- | --- |
| IDLE | start; RELEASE or automatic cleanup that deleted every cache | PREPARE |
| PREPARED | successful PREPARE | ACTIVATE; DEACTIVATE; disconnect |
| ACTIVE | successful ACTIVATE | CHECK finding a changed configuration; DEACTIVATE; disconnect |
| DRAINING | withdrawal, disconnect, failed CHECK/ACTIVATE validation | RELEASE or automatic cleanup once quiescent |

### Deadlines

ACTIVATE and CHECK carry the client's absolute `CLOCK_MONOTONIC` expiry
(`enqueue time + 2000 ms`). The private channel also carries the broker's
framing deadline, and the session uses the earlier expiry. The writer checks
the deadline again after potentially blocking resolver-configuration calls.
Failed private exchanges close the channel so late replies cannot satisfy
another request. Request budgets exclude system suspend.

### Activation and checks

Before ACTIVATE, the daemon verifies module capabilities, consumer readiness,
installed rules, and cache preparation. Startup and resume send no synthetic DNS
queries and inject no reserved answers into core configurations.

- ACTIVATE publishes the prepared policy for the lifetime of its control
  connection. There is no periodic renewal or policy expiration; a stalled
  supervisor with a connected socket leaves its last policy active.
- CHECK validates the active configuration only when a resolver-change event
  arrives; it cannot activate a prepared generation.
- The actor checks inventory changes on ACTIVATE and on event-triggered CHECK,
  and compares DNS settings. A changed network set or DNS configuration replaces
  the published policy with a zero-cache UID guard, starts draining the old
  caches, and returns CACHE_ERROR; clients must prepare a new generation.
- The guard keeps selected queries from falling back to the original shared
  cache during rebuilding. It remains until replaced by a fresh active policy or
  removed by explicit withdrawal or disconnect, and it survives automatic
  topology draining.
- Validation reads each original configuration once per ACTIVATE/CHECK and
  consumes it immediately while checking its isolated copy; these reads are not
  reused across operations. Each owned cache keeps its creation-time
  configuration as the baseline for later comparisons.

### Offline networks

Offline discovery is a successful PREPARE with a zero route count. ACTIVATE
publishes a zero-cache UID guard and the daemon reports `waiting-network` while
core and rules keep running. Selected queries without a cache use the
never-allocated resolver netId `0x7fffffff` and cannot consume the original
shared cache. CHECK compares even an empty inventory, and network changes
rebuild a fresh generation.

### Withdrawal and release

- DEACTIVATE withdraws the snapshot and acknowledges the withdrawal.
- RELEASE waits for both snapshot readers and their accepted resolver workers
  before deleting caches. Failed deletions remain owned for a later retry,
  triggered by network/control events; there is no periodic retry timer.
- Disconnect withdraws and automatically reaps once quiescent. Until that
  release finishes, a new owner's PREPARE answers BUSY with phase DRAINING.
- A private-channel reconnect preserves retained resources but never restores
  the previous policy. Without an acknowledged withdrawal, closing the
  connection requests best-effort cleanup; a blocked module has no guaranteed
  revocation deadline.

## Broker behavior

- The broker forwards one control request at a time, matching the serial actor.
  While a request is outstanding it keeps accepting connections, answering INFO,
  and forwarding events. A reply that misses its deadline closes the private
  channel.
- Client requests are assembled without blocking, within the same 2000 ms
  framing deadline. A partial request that outlives it drops the client.
- New connections have 500 ms to deliver their first header. Bytes already
  received are processed before that deadline is judged.
- A write failure towards the control client, for a reply or an event, drops
  only that client and sends a disconnect to netd; the private channel stays up.
- A HELLO that arrives while a dropped client's reply is still outstanding waits
  for that reply within its own first-header deadline.

## Supervisor contract

- Ordinary transient preparation failures get at most three attempts in total,
  including the first, within the eight-second startup budget shared with
  activation. They are not-ready discovery or reads of real networks and a
  changed original snapshot, and they require IDLE with zero retained caches.
- BUSY/DRAINING while a previous session releases its resources does not consume
  this attempt limit; the startup deadline still bounds the wait.
- Retries advance the generation on the authenticated connection and wait
  through the reactor for a resolver or release-progress event. Waiting remains
  interruptible by stop or child failure.
- Permission, unsupported configuration, unknown errors and incomplete rollback
  of the current preparation fail immediately.
- Hot transitions retry transient preparation after an event, preserving the
  waiting guard. When a network-driven rebuild exceeds its timeout only while
  draining or waiting for a network event, the daemon logs it and keeps waiting
  without a timer instead of stopping the service.

## Energy policy

- Idle broker and netd workers wait for socket and eventfd readiness, never for
  fixed-interval polling. Request framing and control operations keep bounded
  deadlines.
- Steady `waiting-network` has no periodic wakeup or network probe. Cache-miss
  queries do not request inventory rescans; resolver hooks deliver topology and
  configuration events.
- A transient retry waits for such an event and keeps one absolute timeout.
  Pending hot commands wait on socket readiness instead of a 20 ms progress
  timer.
- With flag bit 3, resource draining waits for the release-progress event
  instead of retrying RELEASE; legacy modules without drain events keep a 20 ms
  retry. The actor uses a one-second polling fallback only when a backend lacks
  the drain-wait callback while automatic cleanup waits for quiescence.
- API 26–28 discovery reads only the networks recorded by the resolver
  configure/delete hooks; the full netId range is probed once at backend start.
- Normal suspend does not invalidate an active generation.
