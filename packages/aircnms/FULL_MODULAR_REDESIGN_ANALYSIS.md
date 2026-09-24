# Full Modular Redesign Analysis

This document is a whole-project redesign proposal for the `aircnms` OpenWrt package. It builds on the existing architecture notes and the new AirUI backend reference, but goes deeper into the module boundaries, migration strategy, and practical refactors needed to make the project modular, testable, platform-independent, and safe for both cloud and WebUI control.

## Executive Summary

The current project is a working multi-daemon device agent, but its module boundaries are not clean enough for a full WebUI/backend product surface.

The best target is not one giant daemon. The best target is a modular multi-process architecture with:

- one stable product API surface for WebUI and cloud;
- UBus as the only daemon-to-daemon IPC;
- typed message contracts instead of raw `data`/`size` blobs and topic substring routing;
- shared libraries for queueing, UBus helpers, message envelopes, UCI transactions, and low-level OpenWrt operations;
- a single platform abstraction library, `libairplatform`, hiding MTK, MTK JEDI, QCA, nl80211, ioctl, hostapd, and private driver behavior;
- domain daemons with narrow ownership: cloud, WebUI API, config, telemetry, station/client, command, event, portal, policy/application visibility.

The immediate recommendation is to evolve the existing managers incrementally:

```text
cgwd      -> air-cloud-agent
airuid    -> air-ui-api / product API facade
netconfd  -> air-configd, with portal later extracted to air-portald
netstatsd -> air-telemetryd
stamond   -> air-stationd
cmdexecd  -> air-commandd
eventd    -> air-eventd
acld      -> air-acld / air-usaged
```

Keep current binary/init names during migration and add compatibility UBus aliases for one or more releases.

## Current Architecture Findings

### What Is Good Today

- The package is already split into several daemons, which gives fault isolation and sane procd supervision.
- Shared libraries already exist for common utilities, data structures, logging, MQTT+libev, Unix communication, and DHCP fingerprinting.
- `src/platform/` already separates some MTK, MTK JEDI, and QCA work.
- `netconfd` already centralizes many risky network/wireless writes.
- `netstatsd` and `stamond` already separate periodic stats from station-event monitoring.
- Captive portal code is already internally grouped in `portal_*` modules.

### Main Architectural Problems

| Problem | Evidence in current tree | Redesign direction |
|---|---|---|
| `cgwd` is too central | Registration, MQTT, WebSocket, cloud routing, topic storage, local queueing, and local UBus hub all live under `cgwd`. | Make it a cloud edge only: registration, MQTT/WS/HTTPS, typed cloud-local routing, publish state. |
| Weak local contracts | UBus methods commonly pass `data` and `size` blobs. Cloud routing uses topic/payload heuristics. | Add typed message envelope and method-specific JSON contracts. |
| Duplicate queue logic | `cgwd`, `netconfd`, `netstatsd`, and `cmdexecd` each own similar queue structs, limits, drop handling, and helpers. | Add `libairqueue`. |
| Duplicate UBus scaffolding | Managers repeat `ubus_connect`, `ubus_add_object`, `ubus_invoke`, blob parsing, fd watcher setup, and error logging. | Add `libairubus`. |
| Platform code leaks upward | Manager Makefiles directly compile `../../platform/...`; manager code includes `nl80211`, ioctl, MTK/JEDI ifdefs, and driver command paths. | Add `libairplatform`; managers include only `air_platform.h`. |
| Low-level shell commands are scattered | Many manager/platform files call `system()`/`popen()` for `uci`, `wifi`, `iw`, `iwinfo`, `hostapd_cli`, service restart, reboot, and sysupgrade. | Add low-level OpenWrt/system libraries with structured wrappers and allowlisted execution. |
| `netconfd` has high blast radius | It owns config, ACL, VLAN, NAT, rate limits, portal, scheduling, target-specific work, and shell UCI operations. | Keep configd as orchestrator, extract low-level operations and portal ownership. |
| WebUI needs stable product API | Existing manager APIs are cloud/internal shaped, not frontend shaped. | Add `airuid`/AirUI facade exposing `airui.*` envelope APIs. |
| Observability is uneven | Daemons log but do not consistently expose health, queue metrics, last error, capabilities, or transaction state. | Every daemon gets `status`, `health`, and metrics methods. |
| Packaging drift exists | `airstamond` init path mismatch, `acld` built/installed without matching init script, `tmp/` present in source tree. | Fix packaging before large refactors. |

## Target Modular Architecture

```text
                 Cloud / Controller
                       |
                MQTT / HTTPS / WS
                       |
                air-cloud-agent
                       |
        +--------------+---------------+
        |                              |
   air-ui-api / airuid            local typed UBus
        |                              |
  LuCI / AirUI frontend                 |
                                       v
     +-----------+-----------+----------+-----------+-----------+
     |           |           |          |           |           |
 air-configd air-telemetryd air-stationd air-commandd air-eventd air-acld
     |
 air-portald

 Shared daemon libraries:
 libairmsg, libairubus, libairqueue, libairconfig, libairobserve

 Low-level OpenWrt libraries:
 libairuci, libairsystem, libairnet, libairwifi, libairfirewall, libairprocess

 Platform abstraction:
 libairplatform
   -> mtk backend
   -> mtk_jedi backend
   -> qca backend
```

This design keeps services separate, but makes their boundaries explicit.

## Layered Model

### Layer 1: Product Control Plane

Callers:

- cloud/controller
- LuCI/AirUI WebUI
- mobile app or local CLI in future

These callers speak product intent:

- get dashboard summary
- list clients
- set SSID password
- change LAN IP
- reboot device
- run firmware upgrade
- block client
- enable captive portal
- get statistics

They must not know:

- raw UCI section names;
- `phy0`, `ra0`, `rax0`, `wifi0`;
- hostapd socket paths;
- driver private ioctl;
- cloud MQTT topic internals;
- shell commands.

### Layer 2: High-Level API Facades

Two high-level facades are needed because cloud and WebUI have different security/session models but should share the same internal services.

#### `air-cloud-agent`

Evolves from `cgwd`.

Owns:

- registration/adoption;
- credential refresh;
- MQTT/WebSocket/HTTPS cloud transport;
- cloud topic mapping;
- cloud request normalization;
- local typed routing;
- local-to-cloud publish queue;
- online/offline cloud state.

Does not own:

- network config apply;
- station monitoring;
- stats collection;
- command execution;
- portal lifecycle;
- WebUI response schemas.

#### `airuid` / `air-ui-api`

New AirUI/WebUI backend manager.

Owns:

- stable `airui.*` ubus objects;
- response envelope;
- frontend schema stability;
- read aggregation;
- safe WebUI write validation;
- ACL/session-aware confirmation behavior;
- mapping frontend pages to internal services.

Does not own:

- board-specific writes;
- stats collection loops;
- station event listeners;
- cloud registration;
- portal process internals.

### Layer 3: Domain Services

#### `air-configd`

Evolves from `netconfd`.

Owns:

- desired network/wireless/security config;
- config validation;
- change planning;
- UCI transaction orchestration;
- rollback/confirm state for risky operations;
- VLAN/NAT/rate-limit/firewall coordination;
- board capability checks via `libairplatform`;
- publishing config status.

Should delegate:

- portal instance lifecycle to `air-portald`;
- low-level UCI/netifd/firewall/process work to low-level libraries;
- driver-specific work to `libairplatform`.

#### `air-portald`

Extract from `netconfd` `portal_*` modules after the module boundary is stable.

Owns:

- portal instance metadata;
- template rendering;
- portal network/firewall attachment;
- CoovaChilli lifecycle;
- reference counting by VIF/SSID;
- portal status and recovery on boot.

Short-term option: keep it as an internal `netconfd` module with a clean interface. Long-term option: separate daemon if portal failures should not affect configd.

#### `air-telemetryd`

Evolves from `netstatsd`.

Owns:

- periodic device/VIF/client/neighbor/ethernet counters;
- cached latest stats snapshot;
- one-shot neighbor scan;
- telemetry report intervals;
- cloud publish through `air-cloud-agent`;
- WebUI query snapshots through UBus.

Must expose:

- `air.telemetry.snapshot`
- `air.telemetry.neighbor_scan`
- `air.telemetry.status`

#### `air-stationd`

Evolves from `stamond`.

Owns:

- station connect/disconnect events;
- current station/client runtime table;
- client capability detection;
- random MAC hints;
- DHCP fingerprint integration;
- station history capture;
- optional DNS/flow enrichment.

Must expose:

- `air.station.clients`
- `air.station.client_get`
- `air.station.history`
- `air.station.status`

#### `air-commandd`

Evolves from `cmdexecd`.

Owns:

- command validation and dispatch;
- firmware upgrade workflow;
- reboot/reset/delete/ping/ARP/custom command execution;
- command progress persistence;
- command status publishing.

Must expose:

- `air.command.run`
- `air.command.status`
- `air.command.cancel` where safe

#### `air-eventd`

Evolves from `eventd`.

Owns:

- link/interface/alarm event normalization;
- deduplication;
- event history ring buffer;
- event publish to cloud;
- local UI event query.

`eventd` currently parses `ubus monitor` output using `popen`. Target should subscribe directly to relevant UBus events where possible.

#### `air-acld` / `air-usaged`

Evolves from `acld`.

Owns:

- packet capture;
- DNS/domain mapping;
- application/website usage attribution;
- top application snapshots;
- future application filter observability.

Must expose a read API before AirUI can use it:

- `air.acl.top_apps`
- `air.acl.domain_map`
- `air.acl.clients`
- `air.acl.status`

## Shared Libraries To Add

### `libairmsg`

Common typed message envelope.

Responsibilities:

- message schema and version;
- request id/operation id;
- source/target/type fields;
- JSON and binary payload handling;
- required-field validation;
- error conversion.

Canonical envelope:

```json
{
  "version": 1,
  "id": "op-123",
  "source": "air-cloud-agent",
  "target": "air-configd",
  "type": "config.apply.v1",
  "timestamp_ms": 1786540800000,
  "priority": 3,
  "payload_encoding": "json",
  "payload": {}
}
```

Message type families:

```text
config.apply.v1
config.status.v1
command.run.v1
command.status.v1
telemetry.device.v1
telemetry.vif.v1
telemetry.client.v1
telemetry.neighbor.v1
station.event.v1
station.snapshot.v1
portal.apply.v1
portal.status.v1
event.interface.v1
event.alarm.v1
usage.website.v1
ui.request.v1
ui.response.v1
```

### `libairubus`

Standard UBus helper library.

Responsibilities:

- connect/reconnect;
- register object/method tables;
- integrate UBus fd with libev;
- invoke with timeout;
- parse common request bodies;
- return consistent errors;
- optional synchronous JSON response capture;
- standard logging around missing objects/methods.

This replaces repeated manager-local UBus scaffolding.

### `libairqueue`

Shared bounded queue.

Responsibilities:

- item ownership;
- depth limit;
- byte limit;
- drop-oldest/drop-newest policy;
- priority support later;
- queue metrics;
- thread-safe and non-thread-safe modes;
- libev async/timer integration.

Current managers mostly use `200` entries and `2 MiB` max bytes. Those become config constants, not copied structs.

### `libairconfig`

Config validation and transaction planning.

Responsibilities:

- parse normalized product config;
- validate SSID/radio/network/firewall/rate-limit/portal payloads;
- build UCI operation plans;
- produce dry-run diffs;
- track affected services/configs;
- generate apply IDs;
- record transaction state;
- confirm/rollback helpers.

### `libairopenwrt`

This can be one library or a group of focused libraries:

- `libairuci`
- `libairsystem`
- `libairnet`
- `libairwifi`
- `libairfirewall`
- `libairprocess`

Responsibilities:

- use UCI C API instead of shelling out where possible;
- call `system`, `network`, `network.wireless`, `uci`, `log`, `service`, and `hostapd.*` UBus APIs;
- run necessary commands with fixed argv, timeouts, bounded output, and no string-injection surfaces;
- wrap OpenWrt service reload/restart/status;
- centralize `/proc`, `/sys`, leases, ARP/neigh, bridge FDB parsing.

### `libairplatform`

Stable manager-facing platform API.

Managers include only:

```text
src/platform/api/air_platform.h
src/platform/api/air_platform_types.h
src/platform/api/air_platform_errors.h
```

Backends:

- MTK: `src/platform/mtk`
- MTK JEDI: `src/platform/mtk_jedi`
- QCA: `src/platform/qca`

Responsibilities:

- platform capability discovery;
- radio/VIF discovery;
- station/client stats;
- neighbor scan;
- survey/channel utilization;
- runtime channel switch;
- runtime TX power;
- client disconnect;
- platform ACL operations;
- rate limit ioctl/driver operations;
- platform-specific config apply hooks.

Rules:

- no manager source includes MTK/QCA/JEDI headers;
- no vendor structs cross above platform layer;
- no dummy data is returned as real data;
- unsupported capability is explicit;
- platform maps logical IDs to physical names.

### `libairobserve`

Common observability helpers.

Responsibilities:

- daemon status model;
- uptime;
- build info;
- last error;
- queue metrics;
- operation counters;
- health/dependency states;
- structured audit/event logging.

Every daemon should expose the same base status shape.

## Public API Strategy

### Product APIs

AirUI should expose:

```text
airui.system
airui.status
airui.network
airui.mode
airui.security
airui.maintenance
```

Cloud can expose internal high-level APIs:

```text
air.cloud
air.config
air.telemetry
air.station
air.command
air.event
air.acl
air.portal
```

These two surfaces should share the same domain services underneath.

### Compatibility APIs

Keep aliases during migration:

```text
cgwd.netstats
cgwd.netinfo
cgwd.netaction
cgwd.cmdexec.event
cgwd.cmdexec.config
netconfd.set.cgwd.conf
netconfd.set.cgwd.acl
netconfd.set.cgwd.rl
cmdexecd.cmd
netstatsd.neighbor.trigger
netstatsd.neighbor.scan
```

Compatibility wrappers should translate old calls into typed envelopes internally.

## Service Ownership Matrix

| Feature | API owner | Domain owner | Low-level/platform owner |
|---|---|---|---|
| Cloud registration | `air.cloud` | `air-cloud-agent` | `libairuci`, `libairsystem` |
| WebUI health/capabilities | `airui.system` | `airuid` | all service `status` APIs |
| Dashboard summary | `airui.status` | `airuid` aggregation | telemetry/station/OpenWrt |
| Wireless read | `airui.network` | `airuid` aggregation | UCI, netifd, `air-telemetryd` |
| Wireless write | `airui.network` | `air-configd` | `libairconfig`, `libairplatform` |
| LAN/WAN/routes | `airui.network` / `air.config` | `air-configd` | `libairnet`, `libairuci` |
| Clients | `airui.status` | `air-stationd` | hostapd, DHCP, ARP, platform |
| Statistics | `airui.status` | `air-telemetryd` | `libairplatform` |
| Captive portal | `airui.security` / `air.portal` | `air-portald` | UCI, firewall, process |
| Firewall/MAC/IP filter | `airui.security` / `air.config` | `air-configd` | firewall, hostapd, platform ACL |
| URL/app usage | `airui.security` / `air.acl` | `air-acld` | pcap, DNS map, optional DPI |
| Reboot/reset | `airui.maintenance` / `air.command` | `air-commandd` | `libairsystem` |
| Firmware upgrade | `airui.maintenance` / `air.command` | `air-commandd` | sysupgrade wrapper |
| Events/alarms | `airui.status` / `air.event` | `air-eventd` | UBus subscriptions, netifd |

## Redesign Needed By Current Manager

### `cgwd`

Keep:

- registration;
- cloud transport;
- MQTT/WebSocket handling;
- cloud publish queue.

Change:

- replace topic/payload substring routing with typed message routing;
- move common queue code to `libairqueue`;
- move UBus tx/rx helper code to `libairubus`;
- expose `air.cloud.status` and `air.cloud.controller_status`;
- stop knowing detailed config payload internals beyond message type;
- keep old `cgwd.*` UBus methods as wrappers.

Target modules:

```text
cloud_registration.c
cloud_transport_mqtt.c
cloud_transport_ws.c
cloud_topic_registry.c
cloud_router.c
cloud_publish_queue.c
cloud_status.c
```

### `netconfd`

Keep:

- config orchestration;
- existing board-specific behavior as the initial backend source;
- portal modules short term.

Change:

- split parser, validator, planner, applier, and status modules;
- add safe transaction model for all risky writes;
- move portal behind `air_portal_*` interface, then optionally out to `air-portald`;
- move UCI/shell operations into low-level libraries;
- move platform operations into `libairplatform`;
- add JSON UBus methods usable by AirUI, not only binary/cloud `set.cgwd.*`.

Target modules:

```text
config_ubus.c
config_validate.c
config_plan.c
config_apply.c
config_transaction.c
config_status.c
config_wireless.c
config_network.c
config_security.c
```

### `netstatsd`

Keep:

- periodic stats collection;
- neighbor scan;
- platform stats reuse.

Change:

- maintain latest stats snapshot cache;
- expose query methods for AirUI;
- move platform stats to `libairplatform`;
- move publish queue to `libairqueue`;
- publish typed telemetry messages.

Target methods:

```text
air.telemetry.status
air.telemetry.snapshot
air.telemetry.neighbor_scan
air.telemetry.client_snapshot
air.telemetry.vif_snapshot
```

### `stamond`

Keep:

- station event monitoring;
- history capture;
- DHCP fingerprint/capability enrichment.

Change:

- separate event listener from station table and history store;
- move nl80211 listener/platform-specific station event code to platform or low-level API boundary;
- expose current client table to AirUI;
- publish typed station events.

Target methods:

```text
air.station.status
air.station.clients
air.station.client_get
air.station.history
```

### `cmdexecd`

Keep:

- command dispatch;
- firmware upgrade and reboot workflows;
- command status reports.

Change:

- split command parser from command executor;
- move shell/system operations to `libairsystem`/`libairprocess`;
- persist command state under `/tmp/aircnms` or UCI where needed;
- expose local status for AirUI maintenance pages;
- make destructive actions require typed confirmation tokens.

### `eventd`

Keep:

- event normalization and deduplication.

Change:

- replace `popen("ubus monitor")` parsing with direct UBus event subscription where practical;
- keep a ring buffer for UI logs/events;
- expose status/events methods;
- publish typed event messages to cloud agent.

### `acld`

Keep:

- pcap capture;
- DNS/IP mapping;
- application usage accounting.

Change:

- install/procd decision must be explicit;
- expose UBus query methods;
- persist or snapshot top application usage;
- integrate with future URL/application filter policy service.

## State And Persistence Model

Use one predictable root:

```text
/tmp/aircnms/
  runtime/
    cloud_state.json
    apply/
    command/
    telemetry/
    station/
    portal/
  sockets/
  uploads/
  support/
```

Use UCI for durable config:

```text
aircnms             cloud/device registration state
airui              WebUI/product settings
airui_filter       URL/domain rules
airui_policy       access control/session/random MAC/freeze
airui_qos          bandwidth limits
airui_parental     parental profiles
airui_devices      known device labels
```

Use native OpenWrt configs as source of truth:

```text
network
wireless
firewall
dhcp
system
uhttpd
dropbear
```

Separate:

- desired config;
- staged config;
- last-applied config;
- runtime health;
- cloud connection state;
- command progress;
- apply/rollback state;
- audit/event history.

## Safe Transaction Model

All risky configuration writes should use one transaction engine.

Flow:

1. Receive request with `request_id`.
2. Parse payload into typed structs.
3. Validate fields.
4. Check platform capabilities.
5. Build operation plan.
6. If `dry_run:true`, return diff/warnings only.
7. Save rollback snapshot.
8. Apply UCI changes to affected configs.
9. Commit affected configs.
10. Reload/restart only affected services.
11. Verify runtime state.
12. Return state and `apply_id`.
13. Require confirmation where management can be lost.
14. Roll back on timeout/failure.
15. Audit result.

Risky groups:

- LAN IP/DHCP changes;
- Wi-Fi SSID/security changes;
- firewall default policy/rules;
- VLAN/NAT changes;
- portal network changes;
- management HTTP/HTTPS/SSH settings;
- firmware/reset/reboot.

## Error Model

Use one structured error model across all new APIs:

```json
{
  "code": "invalid_ip",
  "field": "lan.ip",
  "message": "IPv4 address is invalid",
  "source": "air-configd",
  "detail": null
}
```

Common codes:

```text
invalid_argument
invalid_ip
invalid_mac
invalid_cidr
invalid_port
invalid_schedule
not_found
unsupported
backend_unavailable
timeout
busy
apply_failed
rollback_started
rollback_failed
permission_denied
confirmation_required
lockout_risk
insufficient_space
firmware_invalid
```

## Observability Requirements

Every daemon must expose:

```text
<object>.status
<object>.health
```

Common status shape:

```json
{
  "daemon": "air-configd",
  "version": "0.1.0",
  "state": "online",
  "uptime_seconds": 1234,
  "queue": {
    "depth": 0,
    "bytes": 0,
    "drops": 0
  },
  "last_error": null,
  "dependencies": [
    { "name": "ubus", "state": "online" },
    { "name": "libairplatform", "state": "online" }
  ]
}
```

Logs should include:

- request id;
- operation id;
- message type;
- source/target;
- method;
- result;
- error code;
- elapsed time;
- affected config/service.

## Directory Layout Target

Recommended final source layout:

```text
src/
  apps/
    cloud-agent/
    ui-api/
    configd/
    portald/
    telemetryd/
    stationd/
    commandd/
    eventd/
    acld/

  libs/
    airmsg/
    airubus/
    airqueue/
    airconfig/
    airopenwrt/
    airobserve/
    common/
    ds/
    log/
    mosqev/
    dhcpfp/

  platform/
    api/
    mtk/
    mtk_jedi/
    qca/

  include/
    air_model/

files/
  etc/init.d/
  etc/airpro/
  usr/sbin/

docs/
  architecture/
  api/
  migration/
```

Intermediate layout can keep `src/managers/*` while introducing the new libraries.

## Build System Redesign

Current manager Makefiles directly compile platform files. Target:

1. Build common libraries.
2. Build low-level OpenWrt libraries.
3. Build exactly one `libairplatform` backend.
4. Build domain daemons linking to stable libraries.
5. Install compatibility binary names until package rename is complete.

Managers should link:

```text
-lairmsg -lairubus -lairqueue -lairconfig -lairopenwrt -lairplatform -lairobserve
```

Managers should not compile:

```text
../../platform/mtk/...
../../platform/mtk_jedi/...
../../platform/qca/...
```

## Testing Strategy

### Unit Tests

Add host-buildable tests for:

- message envelope parsing/encoding;
- queue drop policy;
- UBus request parsing helpers;
- IP/MAC/CIDR/schedule validators;
- UCI operation plan generation;
- config transaction rollback state;
- portal reference counting;
- command confirmation token logic;
- platform capability mapping;
- AirUI response envelope.

### Integration Tests

Use mocked UBus/platform/OpenWrt APIs:

- cloud config -> configd apply -> status publish;
- WebUI wireless_set -> configd dry-run/apply -> AirUI envelope;
- telemetry snapshot -> AirUI statistics response;
- station event -> station table -> clients API;
- portal assign/release lifecycle;
- command firmware upgrade status flow.

### Device Smoke Tests

On target:

```sh
ubus list
ubus call air.cloud status '{}'
ubus call air.config status '{}'
ubus call air.telemetry snapshot '{}'
ubus call air.station clients '{}'
ubus call airui.system health '{}'
ubus call airui.status summary '{}'
```

Also test:

- boot startup order;
- cloud offline queue behavior;
- MQTT reconnect;
- Wi-Fi apply and rollback;
- LAN IP change rollback;
- VLAN/NAT apply;
- captive portal assign/release;
- station connect/disconnect;
- firmware upgrade status across reboot.

## Migration Plan

### Phase 0: Stabilize Current Tree

Goal: remove drift before architecture work.

Tasks:

- Fix `airstamond` init path mismatch.
- Decide whether `acld` should be installed and started; add init script or stop installing binary.
- Move or ignore generated `tmp/` content.
- Add basic `status` UBus methods to current managers.
- Add smoke test script for installed daemons.

### Phase 1: Add Common Contracts

Goal: new work uses clean contracts.

Tasks:

- Add `libairmsg` envelope.
- Add shared error codes.
- Add `libairubus` helper.
- Add AirUI response envelope helper in `airuid`.
- Keep old methods as wrappers.

### Phase 2: Unify Queues And Observability

Goal: reduce repeated infrastructure code.

Tasks:

- Add `libairqueue`.
- Convert `cgwd`, `netconfd`, `netstatsd`, `cmdexecd` queues.
- Add `libairobserve`.
- Expose queue metrics and last-error fields.

### Phase 3: Platform Boundary

Goal: stop platform leakage.

Tasks:

- Define `src/platform/api/air_platform.h`.
- Build `libairplatform` with current backend code behind wrappers.
- Convert `netstatsd` first, because stats calls are already platform-like.
- Convert `stamond` station info/events.
- Convert `netconfd` runtime radio/VIF/ACL/rate-limit/channel operations.

### Phase 4: Low-Level OpenWrt Libraries

Goal: stop scattering shell/UCI logic.

Tasks:

- Add UCI C helper wrappers.
- Add netifd/wireless/firewall/service wrappers.
- Add command runner with fixed argv, timeout, output cap.
- Replace high-risk `system()` and `popen()` paths in `netconfd`, `cmdexecd`, and `cgwd`.

### Phase 5: Domain API Surfaces

Goal: make managers reusable by cloud and WebUI.

Tasks:

- Add `air.config.validate/apply/status`.
- Add `air.telemetry.snapshot/neighbor_scan`.
- Add `air.station.clients/client_get/history`.
- Add `air.command.run/status`.
- Add `air.acl.top_apps/status`.
- Implement AirUI P0 APIs by calling these services.

### Phase 6: Transaction Engine

Goal: safe writes.

Tasks:

- Implement `libairconfig` plan/diff/apply/confirm/rollback.
- Route AirUI and cloud writes through the same engine.
- Add lockout-risk checks.
- Add audit events.

### Phase 7: Portal Extraction

Goal: reduce `configd` blast radius.

Tasks:

- Freeze `air_portal_*` internal interface.
- Add portal status/recover tests.
- Extract to `air-portald` only after the module is stable.

### Phase 8: Rename/Repackage

Goal: finish modular structure.

Tasks:

- Move `src/managers` to `src/apps`.
- Move docs to `docs`.
- Rename UBus objects to `air.*`.
- Keep compatibility aliases for a release.
- Update init/binary names consistently.
- Remove legacy `libunixcomm` service IPC if unused.

## Suggested First Implementation Cut

For the current AirUI effort, avoid waiting for the full redesign. Build the first cut in a way that aligns with the target:

1. Add `airuid` with stable `airui.*` APIs.
2. Add response envelope and UBus client helper local to `airuid`.
3. Implement read APIs directly from OpenWrt and existing manager query methods.
4. Add missing query methods to `netstatsd` and `stamond` only where needed.
5. For writes, call `netconfd` through new JSON-oriented methods instead of duplicating risky UCI logic.
6. As soon as two daemons need the same helper, promote it to `src/libs/airubus`, `airmsg`, or `airqueue`.

This keeps AirUI moving while creating the first real modular seams.

## Key Decisions Needed

1. Should `airuid` be the only local WebUI API, or should cloud also eventually call the same product APIs?
2. Should portal become a separate daemon immediately, or stay as a clean internal module first?
3. Should `libairplatform` be built as one selected backend per image, or should one image support multiple backends dynamically?
4. Should `libunixcomm` be retired from service IPC completely, or kept for a non-UBus internal use case?
5. Which board is the migration reference target: MTK, MTK JEDI, or QCA?
6. How long must old UBus method names remain compatible with cloud/backend deployments?

## Recommended Architecture Decision

Adopt this rule set for all new work:

1. Product APIs live at `airui.*` and `air.*`.
2. Local daemon-to-daemon IPC is UBus only.
3. Every local request has a typed envelope or method-specific JSON schema.
4. Risky writes go through `air-configd` transaction logic.
5. Platform-specific work goes through `libairplatform`.
6. OpenWrt shell/system work goes through low-level wrappers.
7. Every daemon exposes status/health/metrics.
8. Compatibility wrappers are allowed; new feature logic should not be built on legacy blob APIs.

This gives the project a modular path without a disruptive rewrite.

