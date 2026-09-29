# `air-onbd` Implementation Strategy

## Document status

| Field | Value |
|---|---|
| Component | AIROS / AirCNMS onboarding coordinator |
| Daemon | `air-onbd` |
| Source directory | `packages/aircnms/src/managers/onbd/` |
| Ubus object | `air.onboarding` |
| Persistent configuration | `/etc/config/aircnms`, named section `onboarding` |
| Runtime state | `/run/air-onbd/` |
| Initial rollout mode | Shadow mode |
| Captive portal | Outside this implementation scope |
| Purpose | Introduce a reliable, reboot-safe onboarding coordinator without duplicating cgwd or netconfd responsibilities |

## 1. Purpose

The current AP onboarding path works, but responsibility is divided between boot scripts, `air-cgwd`, `air-netconfd`, UCI flags, MQTT state, and cloud responses. There is no single component that can answer all of these questions consistently:

- Is the AP factory-new, enrolling, enrolled, operational, degraded, or recovering?
- Does it have an Ethernet link, a DHCP address, a default route, DNS, cloud HTTPS access, and MQTT connectivity?
- Was cloud registration accepted, pending claim, rejected, or temporarily unavailable?
- Was configuration merely queued, or was it applied and verified?
- Is it safe to disable the onboarding SSID?
- Should a failed operation be retried, rolled back, or exposed to an operator?
- After a reboot, from which durable checkpoint should onboarding resume?

`air-onbd` will become the authoritative coordinator for those decisions. It will consume facts from existing components and issue bounded commands through defined ubus contracts. It will not replace registration, MQTT, or network configuration implementations.

## 2. Decision

Implement the hybrid architecture:

- A small event-driven C daemon named `air-onbd` owns onboarding policy and lifecycle.
- `air-cgwd` continues to own cloud registration, credentials, MQTT, cloud topics, and cloud message transport.
- `air-netconfd` continues to own validation, UCI mutation, Wi-Fi/network application, runtime verification, ACL, VLAN, radio and rate-limit behavior.
- Narrow shell helpers handle board-specific LED and recovery-network operations only.
- `/etc/config/aircnms` remains the single AirCNMS UCI package. A named `config onboarding 'onboarding'` section stores durable coordinator state.
- Transient state is stored under `/run/air-onbd/` and is recreated on boot.

This design minimizes duplicate logic and permits a low-risk shadow-mode rollout before `air-onbd` receives control of registration, recovery SSIDs or rollback.

## 3. Current implementation baseline

### 3.1 Boot and service management

The AirCNMS OpenWrt package currently installs procd services for:

- `air-cgwd`
- `air-netconfd`
- `air-netstatsd`
- `air-stamond`
- `air-eventd`
- `air-cmdexecd`
- `airuid`

`airinit` currently starts:

- `air_led_state.sh` as a long-running process
- `air_setmac_ssid.sh` as a one-shot process
- `air_ssid_check.sh` as a one-shot process

Most AirCNMS daemons start at priorities 96–99. This is ordering by start number, not readiness. The new coordinator must verify ubus objects and interfaces instead of assuming that earlier services are ready.

### 3.2 Current cgwd lifecycle

Cgwd currently exposes only three device states:

```text
DISCOVERY
NOT_REGISTERED
REGISTERED
```

During `DISCOVERY`, cgwd checks the stored device ID and may perform registration. `REGISTERED` initializes MQTT, starts its worker, and sets the UCI `online` flag. This combines enrollment and connectivity and cannot represent pending claim, configuration progress or operational degradation.

Current registration hardening already provides:

- HTTPS peer and hostname verification
- bounded HTTP timeouts and response size
- duplicate-key JSON rejection
- required identity, credential, topic, broker and port validation
- password decryption without logging credential payloads
- memory cleansing of decrypted password data
- native libuci enrollment persistence
- initial configuration queue admission before credential persistence

These controls must be preserved.

### 3.3 Current netconfd behavior

Netconfd currently:

- accepts configuration through ubus
- validates declared and actual payload size
- copies the payload into owned memory
- inserts it into a bounded in-memory queue
- returns `QUEUED` or `REJECTED`
- processes queued configuration asynchronously
- validates configuration schemas
- applies desired-state radio/VIF configuration
- performs one Wi-Fi reload for a VIF batch
- performs selected runtime verification
- removes poison messages after one processing attempt

The returned `QUEUED` result proves queue admission only. It does not prove `APPLIED`, runtime convergence or rollback.

### 3.4 Default SSID behavior

`air_ssid_check.sh` checks whether the device ID equals the placeholder `XXXXXXXXXX`, then configures default SSIDs. This is a boot-time identity test rather than a complete onboarding policy.

Limitations:

- no DHCP, route, DNS or cloud failure awareness
- no link to configuration application or verification
- no ongoing lifecycle ownership
- no rollback behavior
- uses `nat_network` rather than an isolated recovery network
- cannot distinguish a fresh device from an operational device temporarily disconnected from cloud

### 3.5 LED behavior

`air_led_state.sh` derives three broad conditions using:

- ubus availability
- an ICMP ping to `8.8.8.8`
- `aircnms.@aircnms[0].online`

This is insufficient for the onboarding state model. The script should eventually become a board-specific renderer of an authoritative logical state supplied by `air-onbd`.

### 3.6 Known integration risks

The implementation must address or avoid these risks:

1. Cgwd registration and state-entry work is synchronous and coupled.
2. Netconfd has no durable job ID, revision or completion query.
3. Netconfd queue contents disappear on process restart.
4. Initial credentials are persisted after queue admission, before configuration completion.
5. Incoming MQTT dispatch uses payload substring matching for `cmd` instead of exact topic routing.
6. `online` is not a reliable representation of MQTT connectivity or operational health.
7. Scripts directly mutate UCI and reload Wi-Fi without coordinator ownership.
8. Repeated UCI writes could increase flash wear if transient state is persisted incorrectly.
9. Existing uncommitted cgwd/netconfd hardening must not be overwritten.

## 4. Target architecture

```text
                    +----------------------+
                    |  OpenWrt netifd/ubus |
                    +-----------+----------+
                                | interface facts/events
                                v
+------------+ facts/events +---+----------------+ commands +----------------+
| air-cgwd   +------------->|     air-onbd       +---------->| air-netconfd    |
|            |<-------------+ coordinator/policy |<----------+ config jobs     |
+------------+ registration +---+-----------+----+ status     +----------------+
                                |           |
                                |           +----------> LED helper
                                |
                                +----------------------> recovery helper
                                |
                                +----------------------> /etc/config/aircnms
                                +----------------------> /run/air-onbd
```

### 4.1 `air-onbd` owns

- onboarding lifecycle policy
- connectivity classification
- registration retry scheduling
- pending-claim behavior
- initial configuration job tracking
- recovery SSID policy
- configuration rollback coordination
- derived LED state
- persistent lifecycle checkpoints
- restart/reboot reconciliation
- diagnostics and reason codes

### 4.2 `air-onbd` does not own

- HTTP registration payload construction
- credential decryption or storage
- MQTT protocol or topic subscription
- Wi-Fi/network configuration parsing
- UCI wireless/network mutation
- statistics generation or publication
- captive portal configuration

### 4.3 `air-cgwd` owns

- registration HTTP requests and response validation
- cloud identity and MQTT credentials
- MQTT connection and subscriptions
- online/offline MQTT publication
- exact topic-based cloud message dispatch
- typed registration and MQTT facts exposed to `air-onbd`

### 4.4 `air-netconfd` owns

- configuration schema validation
- normalized desired-state interpretation
- configuration job execution
- wireless/network/UCI changes
- service reload
- runtime convergence checks
- local job status and failure reason
- snapshot and restore mechanics

### 4.5 Board helpers own

- physical LED writes and blink patterns
- Ethernet carrier/speed/duplex diagnostics when not available through ubus
- idempotent recovery interface/SSID activation and deactivation

Helpers must not interpret cloud responses or make onboarding lifecycle decisions.

## 5. State model

A single enum cannot safely represent enrollment, connectivity and configuration. `air-onbd` will maintain three independent axes and derive a public visible state.

### 5.1 Lifecycle state

```c
typedef enum {
    ONBD_LIFECYCLE_FRESH = 0,
    ONBD_LIFECYCLE_ENROLLING,
    ONBD_LIFECYCLE_ENROLLED,
    ONBD_LIFECYCLE_OPERATIONAL,
    ONBD_LIFECYCLE_RECOVERY
} onbd_lifecycle_t;
```

Meanings:

| State | Meaning |
|---|---|
| `FRESH` | No valid completed enrollment is known |
| `ENROLLING` | Registration/claim flow is active |
| `ENROLLED` | Cloud identity and credentials exist, but initial configuration is not verified |
| `OPERATIONAL` | Initial configuration was applied and verified at least once |
| `RECOVERY` | Explicit recovery is required after a failure or operator action |

### 5.2 Connectivity state

```c
typedef enum {
    ONBD_CONN_INITIALIZING = 0,
    ONBD_CONN_NO_LINK,
    ONBD_CONN_DHCP_WAIT,
    ONBD_CONN_DHCP_FAILED,
    ONBD_CONN_NO_DEFAULT_ROUTE,
    ONBD_CONN_DNS_FAILED,
    ONBD_CONN_INTERNET_UNREACHABLE,
    ONBD_CONN_CLOUD_UNREACHABLE,
    ONBD_CONN_MQTT_DISCONNECTED,
    ONBD_CONN_ONLINE
} onbd_connectivity_t;
```

### 5.3 Configuration state

```c
typedef enum {
    ONBD_CONFIG_NONE = 0,
    ONBD_CONFIG_DOWNLOADING,
    ONBD_CONFIG_QUEUED,
    ONBD_CONFIG_APPLYING,
    ONBD_CONFIG_VERIFYING,
    ONBD_CONFIG_APPLIED,
    ONBD_CONFIG_FAILED,
    ONBD_CONFIG_ROLLING_BACK,
    ONBD_CONFIG_ROLLED_BACK,
    ONBD_CONFIG_SUPERSEDED
} onbd_config_state_t;
```

### 5.4 Derived visible state

The ubus/UI visible state is calculated with explicit precedence:

1. critical internal failure
2. active rollback/configuration failure
3. fresh-device link/DHCP/network failure
4. cloud registration state
5. configuration progress
6. operational connectivity status

Examples:

| Lifecycle | Connectivity | Configuration | Visible state |
|---|---|---|---|
| `FRESH` | `DHCP_WAIT` | `NONE` | `DHCP_WAIT` |
| `ENROLLING` | `CLOUD_UNREACHABLE` | `NONE` | `CLOUD_UNREACHABLE` |
| `ENROLLING` | `ONLINE` | `NONE` | `CLAIM_REQUIRED` when cgwd reports pending claim |
| `ENROLLED` | `ONLINE` | `QUEUED` | `CONFIG_QUEUED` |
| `ENROLLED` | `ONLINE` | `VERIFYING` | `CONFIG_VERIFYING` |
| `ENROLLED` | `ONLINE` | `FAILED` | `CONFIG_FAILED` |
| `OPERATIONAL` | `MQTT_DISCONNECTED` | `APPLIED` | `OPERATIONAL_DEGRADED` |
| `OPERATIONAL` | `ONLINE` | `APPLIED` | `OPERATIONAL` |

### 5.5 Operational protection rule

Once `operational_once=1` has been durably stored:

- cloud or MQTT loss changes connectivity state only
- the AP does not return to `FRESH`
- the recovery SSID is not automatically enabled for an ordinary cloud outage
- working configuration is retained
- registration credentials are not cleared

Only factory reset, explicit operator recovery or a defined integrity failure may clear the operational lifecycle marker.

## 6. Persistent and runtime state

### 6.1 Existing UCI package

Use `/etc/config/aircnms`. Do not introduce a second AirCNMS UCI package.

Add a named section:

```uci
config onboarding 'onboarding'
    option schema_version '1'
    option enabled '1'
    option shadow_mode '1'
    option lifecycle 'fresh'
    option operational_once '0'
    option active_attempt_id ''
    option active_config_job_id ''
    option desired_revision '0'
    option applied_revision '0'
    option last_good_revision '0'
    option recovery_ssid_enabled '1'
    option last_failure_code ''
```

Always use named paths such as:

```text
aircnms.onboarding.lifecycle
aircnms.onboarding.operational_once
aircnms.onboarding.shadow_mode
```

Do not use anonymous `@onboarding[0]` references.

### 6.2 Durable write policy

Commit UCI only when a durable checkpoint changes:

- entering a new enrollment attempt
- completing enrollment
- accepting a new initial configuration job
- completing configuration verification
- starting or completing rollback
- first entry into `OPERATIONAL`
- explicit recovery or factory reset

Do not persist:

- DHCP retry counters
- MQTT connected/disconnected flaps
- LED state
- queue depth
- per-probe timestamps
- temporary DNS or cloud probe errors

This prevents unnecessary flash writes.

### 6.3 Runtime state

Use `/run/air-onbd/` for volatile data:

```text
/run/air-onbd/state.json
/run/air-onbd/connectivity.json
/run/air-onbd/diagnostics.json
/run/air-onbd/retry.json
/run/air-onbd/boot_id
```

Files must be written atomically using a temporary file, `fsync` where appropriate, and rename. Runtime files are diagnostic mirrors; in-memory state remains authoritative while the daemon is running.

### 6.4 State schema migration

At daemon startup:

1. Read `schema_version`.
2. If the onboarding section is absent, infer a conservative lifecycle from existing identity data.
3. A valid stored device ID may infer `ENROLLED`, never `OPERATIONAL`.
4. Only a recorded verified checkpoint may set `operational_once=1`.
5. Unknown future schema versions cause safe read-only recovery rather than destructive rewriting.

## 7. Ubus contracts

All contracts must be versioned and return stable machine-readable reason codes.

### 7.1 `air.onboarding`

Methods:

| Method | Purpose |
|---|---|
| `status` | Full state and active identifiers |
| `diagnostics` | Network/cloud/component facts without secrets |
| `retry` | Retry the currently retryable operation |
| `reconcile` | Re-read facts and reconcile persisted/runtime state |
| `recovery.enable` | Explicitly enable recovery access |
| `recovery.disable` | Disable recovery access if safety conditions permit |
| `factory_reset` | Privileged explicit reset flow with confirmation token |

Example `status`:

```json
{
  "schema": "air.onboarding.v1",
  "lifecycle": "ENROLLED",
  "connectivity": "ONLINE",
  "configuration": "VERIFYING",
  "visible_state": "CONFIG_VERIFYING",
  "reason_code": "WAITING_FOR_RUNTIME_VIFS",
  "operational_once": false,
  "attempt_id": "boot-7-registration-2",
  "config_job_id": "cfg-7-18",
  "desired_revision": 18,
  "applied_revision": 17,
  "recovery_ssid_enabled": true,
  "shadow_mode": true,
  "updated_at_monotonic_ms": 623400
}
```

Never expose MQTT passwords, resource keys, Wi-Fi PSKs, RADIUS secrets or complete registration payloads.

### 7.2 Cgwd extensions

Methods:

| Method | Purpose |
|---|---|
| `cgwd.status` | Enrollment, registration-attempt and MQTT facts |
| `cgwd.registration.start` | Begin/reuse a registration attempt |
| `cgwd.registration.cancel` | Cancel a retryable local attempt |
| `cgwd.mqtt.reconnect` | Request a bounded reconnect |

Events:

```text
air.cgwd.registration
air.cgwd.mqtt
```

Registration result enum:

```text
SUCCESS
PENDING_CLAIM
UNKNOWN_DEVICE
MAC_MISMATCH
REJECTED
TEMPORARY_FAILURE
PERMANENT_FAILURE
CANCELLED
```

Example pending claim event:

```json
{
  "schema": "air.cgwd.registration.v1",
  "attempt_id": "boot-7-registration-2",
  "result": "PENDING_CLAIM",
  "reason_code": "PENDING_CLAIM",
  "retry_after": 30,
  "http_status": 200
}
```

The current cloud compatibility response may use HTTP 200 for `PENDING_CLAIM`; classification must use the structured body rather than HTTP status alone.

Cgwd must report enrollment and MQTT connectivity separately. A valid device ID does not prove broker connectivity.

### 7.3 Netconfd extensions

Configuration submission response:

```json
{
  "schema": "air.netconfd.job.v1",
  "accepted": true,
  "status": "QUEUED",
  "job_id": "cfg-7-18",
  "revision": 18,
  "config_hash": "sha256:...",
  "queue_depth": 1
}
```

Methods:

| Method | Purpose |
|---|---|
| `netconfd.status` | Daemon readiness and active/latest job |
| `netconfd.job.status` | Query by `job_id` |
| `netconfd.job.cancel` | Cancel a queued, not applying, job |

Events:

```text
air.netconfd.job
```

Job states:

```text
VALIDATING
QUEUED
SNAPSHOTTING
APPLYING
VERIFYING
APPLIED
FAILED
ROLLING_BACK
ROLLED_BACK
SUPERSEDED
CANCELLED
```

This local job acknowledgement is required now. Cloud-visible configuration acknowledgement is a later protocol extension and is not required for the first `air-onbd` rollout.

## 8. Cgwd changes

### 8.1 Decouple operations from cgwd state entry

Current state transitions perform registration and MQTT initialization directly. Refactor them into operations whose completion is reported through state facts/events.

Requirements:

- no recursive state transition calls from inside a lock
- no long HTTP call in a state setter
- one active registration attempt per boot/process context
- attempt ID included in every result
- stale results ignored by `air-onbd`
- bounded retry owned by `air-onbd`, not duplicated in cgwd

### 8.2 Classify registration responses before success parsing

Before calling the existing full success parser:

1. Parse the top-level response with duplicate-key rejection.
2. Detect structured `code` values.
3. Return typed pending/unknown/mismatch/rejected results without trying to parse credentials.
4. Only the success variant may contain and persist credentials.
5. Treat malformed success payloads as `PERMANENT_FAILURE` with a stable reason.
6. Treat timeouts, DNS errors, TLS connection errors and 5xx as retryable temporary failures.

### 8.3 Preserve credential safety

- Keep TLS verification enabled.
- Keep response size and timeout limits.
- Keep credential redaction and memory cleansing.
- Verify `/etc/config/aircnms` mode is `0600` during package/default setup and health checks.
- Never return credentials from `cgwd.status`.
- Avoid including secrets in ubus events.

### 8.4 Exact MQTT topic dispatch

Replace payload substring dispatch with exact topic matching against the authorized topic table.

Expected behavior:

- configuration topic -> netconfd configuration method
- command topic -> cmdexecd
- RF scan topic -> relevant statistics/scan handler
- ACL topic -> netconfd ACL method
- rate-limit topic -> netconfd rate-limit method
- unknown topic -> reject and log reason code

Payload schema validation occurs after topic selection.

### 8.5 MQTT connectivity facts

Expose:

- configured/not configured
- connecting/connected/disconnected
- last connect/disconnect monotonic timestamp
- last error category
- session/boot identifier
- broker host/port without credentials

Do not use UCI writes for every MQTT state change.

## 9. Netconfd configuration job design

### 9.1 Job metadata

Extend queue items or associate them with a job record:

```c
typedef struct {
    char job_id[48];
    char config_hash[72];
    uint64_t revision;
    int state;
    char reason_code[64];
    uint64_t created_ms;
    uint64_t started_ms;
    uint64_t completed_ms;
} netconf_job_t;
```

### 9.2 Idempotency and revision rules

- Duplicate `revision + hash` returns the existing job/result.
- Same revision with a different hash returns a conflict.
- Older revisions are rejected as stale.
- A newer revision may supersede older queued jobs.
- Never interrupt UCI mutation or `wifi reload` mid-operation.
- After an active job completes, process only the newest retained desired state where safe.
- Without cloud-issued revisions, cgwd may assign a local monotonic revision and SHA-256 payload hash.

### 9.3 Job state persistence

At minimum, persist the active initial-onboarding job metadata before applying changes. Normal later configuration may use a lightweight durable journal.

On restart:

- `QUEUED`: requeue if payload is durably available, otherwise mark failed with `PAYLOAD_LOST_AFTER_RESTART`.
- `APPLYING` or `VERIFYING`: inspect actual UCI/runtime state and reconcile to `APPLIED` or `FAILED_NEEDS_ROLLBACK`.
- `APPLIED`: retain the last successful revision/hash.
- `ROLLING_BACK`: resume or verify rollback.

### 9.4 Result reason codes

Use stable reason codes such as:

```text
OK
INVALID_SCHEMA
INVALID_RADIO
INVALID_VIF
INVALID_SECURITY_MODE
UCI_WRITE_FAILED
NETWORK_RELOAD_FAILED
WIFI_RELOAD_FAILED
RUNTIME_VIF_MISSING
MANAGEMENT_CONNECTIVITY_LOST
STALE_REVISION
REVISION_CONFLICT
SUPERSEDED_BY_NEWER_CONFIG
SNAPSHOT_FAILED
ROLLBACK_FAILED
INTERNAL_ERROR
```

Human messages may change; reason codes must remain stable.

## 10. Snapshot, verification and rollback

### 10.1 Snapshot scope

Before applying the initial onboarding configuration, snapshot:

```text
/etc/config/wireless
/etc/config/network
/etc/config/dhcp
/etc/config/firewall
```

Store:

- `job_id`
- revision/hash
- creation timestamp
- SHA-256 per file
- manifest schema version

Retain a bounded number of snapshots: current transaction plus two last-known-good snapshots is recommended.

### 10.2 Atomicity

- Copy to a temporary snapshot directory.
- Validate every required file and checksum.
- Atomically rename the completed snapshot directory.
- Do not claim `SNAPSHOTTING` success until the manifest is durable.

### 10.3 Runtime verification

Configuration is `APPLIED` only after relevant checks pass:

- expected radios exist and have requested enabled state
- expected VIFs exist
- expected SSIDs match
- security mode is accepted by runtime hostapd
- required bridge/network mappings exist
- management interface remains reachable
- required default route exists
- DNS and cloud HTTPS still work when the configuration is expected to preserve WAN access
- MQTT can reconnect within its independent timeout when required for onboarding completion

Not every check belongs inside netconfd. Netconfd should verify local configuration/runtime convergence; `air-onbd` verifies end-to-end management and cloud connectivity.

### 10.4 Rollback completion

Rollback is complete only when:

1. snapshot checksums validate
2. files are restored atomically
3. network and wireless reloads complete
4. management connectivity is restored or recovery access is available
5. netconfd reports `ROLLED_BACK`
6. `air-onbd` moves lifecycle to `RECOVERY` with a reason code

A failed rollback enters a critical recovery state and must not loop indefinitely.

## 11. Connectivity assessment

### 11.1 Probe order

Use layered facts:

1. ubus is available
2. management interface is present
3. physical carrier when applicable
4. netifd reports interface `up`
5. a usable management address exists
6. a default route exists
7. DNS resolution works
8. HTTPS cloud health/registration endpoint is reachable
9. registration succeeds or returns a typed business result
10. MQTT connects after enrollment

### 11.2 Probe implementation

Prefer ubus/netifd data over parsing shell command output. Use asynchronous subprocess helpers only where OpenWrt libraries or ubus do not expose the needed hardware fact.

Avoid using only `ping 8.8.8.8`; ICMP may be blocked while HTTPS works.

### 11.3 Retry policy

Use bounded exponential backoff with jitter per operation class.

Example defaults:

| Operation | Initial | Maximum | Notes |
|---|---:|---:|---|
| ubus dependency wait | 1 s | 5 s | continuous while booting |
| DHCP readiness | netifd-driven | 60 s threshold | do not repeatedly restart netifd |
| DNS/cloud probe | 2 s | 60 s | jittered |
| registration temporary failure | server `retry_after` or 5 s | 5 min | reset after success |
| pending claim | server `retry_after` | 10 min | recovery SSID stays enabled |
| MQTT reconnect | cgwd-managed transport backoff | bounded | state observed by onbd |
| config retry | operator/policy controlled | limited attempts | never loop destructive apply |

## 12. Recovery SSID and local access

### 12.1 Dedicated recovery network

Do not reuse an operational tenant network. Create dedicated sections, for example:

```text
wireless.airpro_recovery_2g
wireless.airpro_recovery_5g
network.airpro_recovery
dhcp.airpro_recovery
firewall airpro recovery zone/rules
```

Suggested local subnet:

```text
192.168.4.1/24
```

The actual subnet must be conflict-checked against current management networks.

### 12.2 Default SSID identity

The default onboarding SSIDs are band-specific and must use the last six hexadecimal characters of the corresponding radio/interface MAC address:

```text
AirPro-2G-{LAST_6_MAC}
AirPro-5G-{LAST_6_MAC}
```

For example, MAC address `58:7B:E9:24:8B:EA` produces:

```text
AirPro-2G-248BEA
AirPro-5G-248BEA
```

Formatting rules:

- remove MAC separators before extracting the suffix
- take exactly the final six hexadecimal characters
- render the suffix in uppercase
- keep the literal prefixes exactly `AirPro-2G-` and `AirPro-5G-`
- reject an unavailable, malformed, multicast, all-zero or placeholder MAC rather than producing an unstable SSID
- derive the value deterministically so rebooting or restarting `air-onbd` does not rename the SSID

When the 2.4 GHz and 5 GHz interfaces have different assigned MAC addresses, each SSID uses the suffix of its corresponding interface MAC. If the platform exposes only one authoritative base/device MAC during early boot, `air-onbd` may use that same validated suffix for both SSIDs until the radio interface MACs are available. The selected source MACs must be exposed in diagnostics without changing them during onboarding.

### 12.3 Security requirements

- device-specific authentication or controlled local setup credential
- client isolation where supported
- local firewall permitting only approved management endpoints
- no unrestricted forwarding to tenant networks
- no exposure of MQTT or cloud credentials
- idempotent enable/disable operations

### 12.4 Enable policy

Enable recovery access when:

- lifecycle is `FRESH` or `ENROLLING`
- DHCP fails past the defined threshold
- claim is pending
- initial configuration fails or rolls back
- explicit operator recovery is requested
- factory reset occurs

### 12.5 Disable policy

Disable only after all are true:

- enrollment succeeded
- initial configuration job is `APPLIED`
- local runtime verification passed
- management connectivity passed
- `operational_once=1` was durably committed

An ordinary cloud/MQTT outage after operational success must not automatically enable recovery access.

## 13. LED architecture

`air-onbd` chooses a logical LED state. A helper maps the state to board-specific sysfs LEDs.

Logical states:

```text
BOOTING
INITIALIZING
DHCP_WAIT
NETWORK_FAILED
CLOUD_CONNECTING
CLAIM_REQUIRED
UNKNOWN_DEVICE
CONFIG_QUEUED
CONFIG_APPLYING
CONFIG_FAILED
ROLLBACK
OPERATIONAL
OPERATIONAL_DEGRADED
CRITICAL_FAILURE
```

The MT7621 board currently exposes `system`, `wlan2g` and `wlan5g`. Product colors such as amber or white must be validated against real hardware rather than assumed.

Helper rules:

- fixed allowlisted state argument
- no cloud-derived shell interpolation
- bounded execution time
- stable exit codes
- failure affects diagnostics only, not onboarding progress

## 14. Process model and startup

### 14.1 Source layout

```text
packages/aircnms/src/managers/onbd/
├── Makefile
├── inc/
│   ├── onbd.h
│   ├── onbd_state.h
│   ├── onbd_event.h
│   ├── onbd_ubus.h
│   ├── onbd_persist.h
│   ├── onbd_network.h
│   └── onbd_probe.h
└── src/
    ├── main.c
    ├── onbd_state.c
    ├── onbd_event.c
    ├── onbd_ubus.c
    ├── onbd_persist.c
    ├── onbd_network.c
    ├── onbd_cgwd.c
    ├── onbd_netconfd.c
    ├── onbd_recovery.c
    ├── onbd_led.c
    └── onbd_diagnostics.c
```

### 14.2 Installed files

```text
/usr/sbin/air-onbd
/etc/init.d/aironbd
/usr/libexec/air-onbd/led-mtk.sh
/usr/libexec/air-onbd/recovery-mtk.sh
/run/air-onbd/
```

### 14.3 Event loop

Use libev, matching existing managers. The main loop should contain:

- ubus socket watcher
- dependency/reconciliation timer
- retry timers
- child-process completion watchers when helpers are used
- signal handlers

Do not use busy polling or blocking HTTP/configuration execution in the event loop.

### 14.4 Procd service

The procd unit should:

- use `USE_PROCD=1`
- capture stdout/stderr
- use bounded respawn policy
- declare file/UCI reload triggers where appropriate
- start after base ubus/network initialization but still perform its own readiness checks
- create `/run/air-onbd` safely

The first release must set `shadow_mode=1` by default.

## 15. Package build integration

Update the AirCNMS package to:

1. add `BUILD_MGRONBD`
2. compile `src/managers/onbd`
3. install `/usr/sbin/air-onbd`
4. install `/etc/init.d/aironbd`
5. install board helpers under `/usr/libexec/air-onbd/`
6. add safe UCI defaults/migration logic for the named onboarding section
7. avoid overwriting existing `/etc/config/aircnms` during package upgrade

The package must merge defaults only when fields are missing. It must preserve identity, MQTT credentials, topics and current operational configuration.

## 16. Rollout phases

### Phase 0 — Baseline and repository hygiene

Actions:

- record current git commit and dirty-tree inventory
- preserve existing cgwd/netconfd hardening in reviewed commits or patches
- remove generated objects/binaries from version-control consideration
- capture real cloud and board fixtures with secrets removed
- record current boot, registration, retained-config and outage behavior

Exit gate:

- existing changes reproducible
- baseline package builds
- current onboarding and netconfd tests pass
- rollback artifact exists

### Phase 1 — Shadow coordinator

Implement:

- daemon skeleton and procd service
- `air.onboarding status` and `diagnostics`
- three-axis state model
- UCI onboarding section read/migration
- runtime state mirror
- netifd/cgwd/netconfd observation
- structured transition logging

Restrictions:

- no registration command
- no wireless/network mutation
- no default SSID control
- no cgwd/netconfd restart
- no rollback
- legacy LED/SSID scripts remain authoritative

Exit gate:

- derived state agrees with observed reality across test scenarios
- daemon restart/reboot reconciliation works
- no additional operational behavior
- UCI write rate is bounded
- memory and CPU stay within budget

### Phase 2 — Cgwd typed contract

Implement:

- `cgwd.status`
- typed asynchronous registration start/result
- response classification
- registration attempt IDs
- MQTT connectivity events
- exact topic routing

Initially, `air-onbd` observes and may initiate only controlled test registration.

Exit gate:

- pending claim, unknown device, mismatch, temporary failure and success are distinct
- no credential leakage
- stale attempt results ignored
- existing registered devices remain compatible

### Phase 3 — Netconfd job contract

Implement:

- job IDs and state records
- revision/hash idempotency
- job status method and events
- stable failure reasons
- initial job journal/reconciliation
- superseding behavior

Exit gate:

- `QUEUED` and `APPLIED` are demonstrably different
- duplicate delivery is idempotent
- stale/conflicting revisions rejected
- process restart has deterministic recovery

### Phase 4 — Initial configuration verification and rollback

Implement:

- snapshot manifest/checksums
- local apply verification
- end-to-end verification by `air-onbd`
- rollback coordination
- critical failure handling

Exit gate:

- every destructive step has a tested recovery path
- power interruption cases reconcile safely
- management access remains available or recovery mode is entered

### Phase 5 — Recovery network ownership

Implement:

- dedicated recovery UCI sections
- safe helper interface
- lifecycle-driven enable/disable policy
- migration away from `air_ssid_check.sh`

Keep the legacy script packaged but disabled for one rollback window.

Exit gate:

- recovery is available during all fresh-onboarding failures
- recovery disappears only after verified operational state
- operational cloud outage does not reactivate it
- firewall isolation passes

### Phase 6 — LED ownership

Implement logical state-to-renderer integration and disable policy decisions in the legacy LED script.

Exit gate:

- all states have verified board patterns
- unsupported colors documented
- helper failure cannot block onboarding

### Phase 7 — Release candidate

Perform unit, integration, real-board, reboot, fault-injection, resource and upgrade/rollback testing. Promote from shadow mode only after acceptance gates pass.

## 17. Compatibility strategy

### 17.1 Existing enrolled APs

- A valid existing identity may initialize lifecycle as `ENROLLED`.
- Do not automatically mark it `OPERATIONAL` without a verified marker.
- Do not force mass re-registration.
- Do not rotate existing credentials as part of `air-onbd` introduction.
- Continue cgwd’s normal stored-credential startup path.

### 17.2 Current cloud API

- Support HTTP 200 structured `PENDING_CLAIM` responses.
- Continue accepting the existing successful registration response shape.
- Configuration revision may initially be local.
- Cloud-visible `APPLIED`/`FAILED` ACK is deferred but the local data model must be ready for it.

### 17.3 Legacy scripts

- Phase 1: scripts remain active and `air-onbd` only observes.
- Recovery-control phase: `air_ssid_check.sh` becomes disabled by policy but remains installed for rollback.
- LED-control phase: `air_led_state.sh` becomes a renderer or is replaced by the new helper.
- Remove legacy paths only after one successful release/rollback cycle.

### 17.4 UCI upgrade

Package upgrades must add missing onboarding options without replacing `/etc/config/aircnms`. Existing credentials, identity, URLs and topics must remain byte-for-byte unchanged unless an explicit migration requires otherwise.

## 18. Testing strategy

### 18.1 Host unit tests

Test:

- state transition table
- visible-state precedence
- retry/backoff calculation
- stale attempt rejection
- revision/hash comparison
- UCI migration logic through an abstraction
- JSON/ubus response generation
- secret-field exclusion
- restart reconciliation decisions

Use injected interfaces for clock, persistence, ubus calls and helper execution.

### 18.2 Component contract tests

Cgwd:

- every registration outcome
- malformed and duplicate-key JSON
- TLS/DNS/connect/timeout categories
- credential redaction
- exact topic routing
- stale attempt result

Netconfd:

- queue admission
- job lifecycle
- duplicate and conflicting revision
- poison payload
- restart during each job state
- runtime verification failure
- snapshot and rollback

Onbd:

- missing dependency
- inconsistent component facts
- reboot reconciliation
- operational protection
- recovery enable/disable policy

### 18.3 Real-board scenario matrix

At minimum:

| # | Scenario | Expected outcome |
|---:|---|---|
| 1 | Factory reset with healthy network/cloud | Becomes operational; recovery SSID disabled after verification |
| 2 | No Ethernet carrier | `NO_LINK`; recovery access remains available |
| 3 | Carrier but no DHCP | `DHCP_FAILED`; fallback/recovery remains available |
| 4 | Delayed DHCP | Continues without destructive network restart |
| 5 | Address but no route | `NO_DEFAULT_ROUTE` |
| 6 | DNS failure | `DNS_FAILED` |
| 7 | Cloud TLS/DNS failure | `CLOUD_UNREACHABLE`; bounded retry |
| 8 | Unknown serial | `UNKNOWN_DEVICE`; no credentials persisted |
| 9 | Pending claim | `CLAIM_REQUIRED`; respects `retry_after` |
| 10 | Claim approved during polling | Continues same lifecycle safely |
| 11 | Registration timeout after server commit | Idempotent retry; no credential fork |
| 12 | Malformed registration response | Safe failure; no partial credential persistence |
| 13 | Initial config rejected | Enrollment/config states remain distinct |
| 14 | Netconfd unavailable | Retry without blocking main event loop |
| 15 | Config queued then netconfd restarts | Deterministic reconciliation |
| 16 | Wi-Fi reload failure | Job failed and rollback initiated |
| 17 | Runtime VIF missing | Verification fails; recovery retained |
| 18 | Power loss before snapshot completion | Incomplete snapshot ignored safely |
| 19 | Power loss while applying | Reconcile actual UCI/runtime state |
| 20 | Power loss during rollback | Resume/verify rollback |
| 21 | Duplicate retained config | Existing job/result returned |
| 22 | New revision while older queued | Older queued job superseded |
| 23 | Operational AP loses cloud | Operational config retained; no recovery SSID reactivation |
| 24 | Operational AP reboots offline | Remains operational-degraded, not fresh |
| 25 | Explicit operator recovery | Recovery enabled with audit reason |
| 26 | Factory reset after operational use | Durable identity/onboarding state cleared through controlled flow |
| 27 | LED helper failure | Onboarding continues; diagnostic records helper failure |
| 28 | Recovery helper timeout | Bounded failure; no daemon hang |
| 29 | Repeated network flaps | No excessive UCI commits or restart storm |
| 30 | Package rollback | Previous cgwd/netconfd/legacy scripts restore service |

### 18.4 Resource and endurance tests

Measure:

- resident memory
- idle and transition CPU
- file descriptors
- ubus request rate
- UCI commit count
- flash writes during 24-hour network/cloud failure
- log volume and rotation behavior
- queue/job retention bounds

Initial targets:

- no busy polling
- few MiB resident memory
- negligible idle CPU
- bounded helper processes
- no unbounded job/history growth
- no UCI writes for transient connection flaps

### 18.5 Security tests

- ubus methods reject malformed types and oversized fields
- no shell interpolation of cloud-controlled strings
- recovery firewall isolation
- credential files and UCI permissions
- no secrets in logs, ubus or runtime JSON
- exact MQTT topic authorization
- malformed reason/job/attempt IDs rejected
- factory reset command access control

## 19. Observability

Every transition log should be structured and redact secrets:

```text
ONBD_TRANSITION axis=lifecycle from=ENROLLING to=ENROLLED reason=REGISTRATION_SUCCESS attempt_id=...
ONBD_TRANSITION axis=config from=APPLYING to=FAILED reason=WIFI_RELOAD_FAILED job_id=...
ONBD_RECONCILE lifecycle=ENROLLED connectivity=ONLINE config=VERIFYING source=daemon_restart
```

Expose counters through diagnostics:

- state transitions by reason
- registration attempts/results
- config jobs/results
- rollback attempts/results
- dependency loss/recovery
- recovery enable/disable
- ignored stale events
- UCI commits
- helper failures/timeouts

Avoid high-frequency per-poll success logs.

## 20. Failure and reconciliation rules

### 20.1 Stale events

Every asynchronous result must carry an identifier:

- `boot_id`
- `attempt_id`
- `job_id`
- revision/hash

Ignore results that do not match the active operation. Count and log them without changing lifecycle.

### 20.2 Component restart

When cgwd or netconfd disappears:

- record dependency unavailable
- do not immediately destroy working configuration
- retry discovery with backoff
- query status after reappearance
- reconcile using durable identifiers and actual system facts

### 20.3 Daemon restart

On `air-onbd` restart:

1. load durable UCI state
2. create a new boot/process context identifier
3. query netifd, cgwd and netconfd
4. inspect recovery interface state
5. reconcile active attempt/job
6. derive visible state
7. resume only safe retryable work

### 20.4 Inconsistent state

If persisted state and runtime facts conflict, prefer safety:

- valid working operational configuration is not erased
- credentials are not cleared automatically
- recovery access is preserved for incomplete initial onboarding
- destructive apply is not repeated without job/revision evidence
- expose an explicit inconsistency reason code

## 21. Coding rules

- Use bounded buffers and checked copy/format functions.
- Use native libuci, libubus and libev rather than shell commands where possible.
- Use monotonic time for intervals and wall clock only for reporting.
- Never hold locks across ubus calls, helper execution or filesystem I/O.
- Never block the event loop on HTTP, Wi-Fi reload or long helpers.
- Validate every cross-daemon payload and version.
- Keep reason codes stable and testable.
- Make all state transitions pass through one state module.
- Keep platform-specific behavior outside the core coordinator.
- Preserve existing hardening changes and test them before integration.

## 22. File-level implementation map

### New files

| Path | Purpose |
|---|---|
| `src/managers/onbd/Makefile` | Build `air-onbd` |
| `src/managers/onbd/inc/onbd*.h` | Coordinator contracts and types |
| `src/managers/onbd/src/*.c` | State, events, persistence, probes and integrations |
| `files/aironbd` | Procd service |
| `files/air-onboarding-led-mtk.sh` | MT7621 LED renderer |
| `files/air-onboarding-recovery-mtk.sh` | Bounded board recovery helper |
| `tests/onbd/*` | Host unit/contract tests |

### Existing files to modify

| Path | Change |
|---|---|
| `packages/aircnms/Makefile` | Build/install daemon, service and helpers |
| `src/managers/cgwd/inc/cgw.h` | Typed registration/MQTT status API |
| `src/managers/cgwd/src/cgw_state_mgr.c` | Decouple long operations from state entry |
| `src/managers/cgwd/src/cgw_cloud_reg.c` | Response classification and attempt results |
| `src/managers/cgwd/src/cgw_ubus.c` | New status/registration methods and events |
| `src/managers/cgwd/src/cgw_msgrx.c` | Exact topic dispatch |
| `src/managers/cgwd/src/cgw_mqtt.c` | Connectivity events and correct online/offline semantics |
| `src/managers/netconfd/inc/netconf.h` | Job types/APIs |
| `src/managers/netconfd/src/netconf_ubus_rx.c` | Job-aware queue response/status methods |
| `src/managers/netconfd/src/netconf_queue.c` | Job metadata, idempotency and superseding |
| `src/managers/netconfd/src/netconf_process_msg.c` | Job transitions and result propagation |
| `src/managers/netconfd/src/netconf_set_process.c` | Stable reason codes and verification result |
| `files/airinit_mtk` | Gradual retirement of legacy policy scripts |
| `files/air_ssid_check.sh` | Retain for rollback, then disable/remove |
| `files/air_led_state.sh` | Convert to renderer or retire after LED phase |

## 23. Acceptance gates

### Gate S — Shadow mode

Pass requires:

- package builds reproducibly
- `air-onbd` remains stable through reboot and dependency restart
- state derivation matches manual observations
- no configuration/SSID behavior change
- bounded resource and flash-write behavior

### Gate C — Cgwd contract

Pass requires:

- all response classifications tested
- exact topic dispatch tested
- credentials never exposed
- retry/stale-result behavior deterministic
- existing enrolled AP compatibility

### Gate N — Netconfd jobs

Pass requires:

- queue admission, application and verification are distinct
- duplicate/stale/conflicting revisions behave correctly
- restart reconciliation tested
- local `APPLIED`/`FAILED` evidence available

### Gate R — Recovery and rollback

Pass requires:

- initial configuration failure restores access
- rollback power-loss tests pass
- recovery network isolation passes
- operational outage protection passes

### Gate RC — Release candidate

Pass requires:

- complete board scenario matrix
- upgrade and rollback validation
- resource/endurance targets
- no unresolved critical/high defects
- documented limitations and operator runbook

## 24. Recommended first implementation slice

Implement Phase 1 only:

1. create `src/managers/onbd`
2. build/install `/usr/sbin/air-onbd`
3. add `/etc/init.d/aironbd`
4. add the named `aircnms.onboarding` section if missing
5. implement the three independent state axes
6. query netifd, current cgwd state and netconfd availability
7. expose `air.onboarding status` and `diagnostics`
8. write structured transition logs
9. add host unit tests for state derivation and persistence migration
10. enable `shadow_mode=1` by default

The first slice must not change radio/network configuration, initiate registration, control recovery SSIDs, restart other daemons or perform rollback. Its purpose is to prove that `air-onbd` observes and reconciles the existing system correctly before it receives authority.

## 25. Definition of done

Approach 4 is complete when:

- `air-onbd` is the documented authoritative onboarding coordinator
- cgwd exposes typed enrollment and MQTT facts
- netconfd exposes durable, idempotent configuration jobs
- initial configuration is verified before recovery access is disabled
- failed initial configuration has a tested rollback path
- fresh-device failures keep safe local recovery available
- operational APs remain operational during temporary cloud outages
- reboot and process restart reconciliation are deterministic
- state and failure reasons are observable without exposing secrets
- the complete real-board, security, endurance, upgrade and rollback suites pass
