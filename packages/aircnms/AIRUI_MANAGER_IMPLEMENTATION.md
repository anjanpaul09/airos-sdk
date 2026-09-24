# AirUI Manager Implementation

This document describes the current `airuid` manager implementation in the
`aircnms` OpenWrt package, the UBus API it exposes for AirUI, and the proposed
implementation phases to turn it into the full product API facade.

## Current Status

`airuid` is a standalone daemon installed as `/usr/sbin/airuid` and supervised by
procd through `/etc/init.d/airuid`.

The manager currently acts as an upper-layer AirUI UBus facade. It exposes
frontend-friendly `airui.*` UBus objects, wraps replies in a consistent response
envelope, and delegates wireless configuration work to OpenWrt default UBus
objects such as `uci`, `network.wireless`, and `network`.

The working implementation today is focused on wireless configuration:

- read wireless UCI and runtime status;
- edit existing wireless sections;
- add new `wifi-iface` or `wifi-device` sections;
- delete wireless sections;
- commit wireless config;
- apply changes through `ubus call network reload`;
- support `dry_run` validation for add/edit/delete;
- return structured success/error responses for UI consumption.

Other AirUI domains are registered as placeholders and currently return
`unsupported`.

## Source Layout

```text
src/managers/airuid/
├── Makefile
├── inc/
│   ├── airuid.h
│   ├── airui_network.h
│   ├── airui_response.h
│   └── airui_ubus_client.h
└── src/
    ├── main.c
    ├── airui_ubus.c
    ├── airui_network.c
    ├── airui_response.c
    └── airui_ubus_client.c

files/airuid
```

## Build And Packaging

The package `Makefile` builds `airuid` through:

```make
BUILD_MGR_AIRUID:= $(MAKE) -C $(PKG_BUILD_DIR)/managers/airuid $(MAKE_PACKAGE_ARGS)
```

The binary is installed as:

```make
$(CP) $(PKG_BUILD_DIR)/managers/airuid/airuid $(1)/usr/sbin/airuid
```

The init script is installed as:

```make
$(INSTALL_BIN) ./files/airuid $(1)/etc/init.d
```

`src/managers/airuid/Makefile` links against:

- `libev`
- `librt`
- `libjansson`
- `liblog`
- `libcommon`
- `libnl-3`
- `libnl-genl-3`
- `libubus`
- `libubox`
- `libjson-c`
- `libblobmsg_json`

## Runtime Lifecycle

`main.c` initializes logging, installs `SIGTERM` and `SIGINT` handlers, starts
the AirUI UBus service, then enters the default `libev` loop.

Shutdown path:

1. signal handler calls `ev_break`;
2. `airui_ubus_service_cleanup()` stops the UBus watcher and frees the UBus
   context;
3. signal watchers are stopped;
4. the default ev loop is destroyed;
5. process exits.

The procd init script:

```sh
START=98
USE_PROCD=1
PROG=/usr/sbin/airuid
```

It starts `airuid` with stdout/stderr logging enabled and respawn configured.

## UBus Object Model

`airui_ubus.c` registers these UBus objects:

```text
airui.system
airui.network
airui.status
airui.mode
airui.security
airui.maintenance
```

### Implemented Methods

```text
airui.system health
airui.system capabilities
airui.network wireless_config
airui.network wireless_set
airui.network wireless_add
airui.network wireless_delete
```

### Placeholder Methods

These methods are registered but return an `unsupported` error:

```text
airui.system apply_status
airui.network lanwan_config
airui.network lanwan_set
airui.status summary
airui.status clients
airui.status statistics
airui.mode controller_status
airui.security rules
airui.maintenance device_management_get
airui.maintenance reboot
```

## Response Envelope

All AirUI replies are built through `airui_response.c`.

Success response:

```json
{
  "ok": true,
  "data": {},
  "warnings": [],
  "errors": [],
  "meta": {
    "timestamp": 1750000000,
    "source": "live",
    "schema": 1
  }
}
```

Error response:

```json
{
  "ok": false,
  "data": {},
  "warnings": [],
  "errors": [
    {
      "code": "invalid_argument",
      "field": "section",
      "message": "Wireless section is required"
    }
  ],
  "meta": {
    "timestamp": 1750000000,
    "source": "live",
    "schema": 1
  }
}
```

Current error codes:

```text
invalid_argument
backend_unavailable
unsupported
error
```

## UBus Client Helper

`airui_ubus_client.c` provides a small wrapper around OpenWrt UBus calls:

```c
int airui_ubus_call_json(struct ubus_context *ctx,
                         const char *object,
                         const char *method,
                         struct blob_buf *request,
                         struct airui_ubus_result *result);
```

Behavior:

- validates required arguments;
- resolves object IDs with `ubus_lookup_id`;
- calls the method using `ubus_invoke`;
- captures the response blob as formatted JSON;
- stores response JSON and status in `struct airui_ubus_result`;
- uses a 5000 ms timeout.

`airui_ubus_object_exists()` is used by health and capabilities checks.

## Health And Capabilities

### `airui.system health`

Returns daemon state and backend availability:

```json
{
  "ok": true,
  "data": {
    "state": "running",
    "uci_available": true,
    "network_wireless_available": true
  },
  "warnings": [],
  "errors": [],
  "meta": {}
}
```

Example:

```sh
ubus call airui.system health
```

### `airui.system capabilities`

Returns currently registered AirUI objects and the availability of OpenWrt
backend objects:

```json
{
  "ok": true,
  "data": {
    "objects": {
      "airui.system": true,
      "airui.network": true,
      "airui.status": true,
      "airui.mode": true,
      "airui.security": true,
      "airui.maintenance": true,
      "openwrt.uci": true,
      "openwrt.network.wireless": true
    },
    "schema": 1
  },
  "warnings": [],
  "errors": [],
  "meta": {}
}
```

Example:

```sh
ubus call airui.system capabilities
```

## Wireless API

Wireless operations are implemented in `airui_network.c`.

### Supported Input Fields

```text
section     string  UCI section name, required for set/delete, optional for add
disabled    bool    Converted to UCI string "1" or "0"
ssid        string  Maximum 32 characters
encryption  string
key         string  Maximum 63 characters
network     string
channel     string
htmode      string
country     string
device      string  Required when adding a wifi-iface
mode        string
type        string  Add only: wifi-iface or wifi-device, default wifi-iface
dry_run     bool    Validate and return without changing config
```

### Section Validation

Section names must be non-empty and may contain only:

```text
A-Z a-z 0-9 _ -
```

This prevents accidental malformed UCI paths and blocks shell-like characters
from entering UCI section names.

### Apply Behavior

For non-dry-run write operations, the current flow is:

```text
uci add/set/delete
ubus call uci commit '{"config":"wireless"}'
ubus call network reload
```

The manager intentionally uses OpenWrt default UBus calls as the lower layer.
It does not write files directly and does not call `wifi` or driver-specific
commands directly.

### `airui.network wireless_config`

Returns both persistent UCI config and runtime wireless status.

Backend calls:

```text
ubus call uci get '{"config":"wireless"}'
ubus call network.wireless status
```

Example:

```sh
ubus call airui.network wireless_config
```

Response data:

```json
{
  "uci": {},
  "runtime": {}
}
```

`uci` and `runtime` contain the parsed JSON replies from the underlying OpenWrt
UBus calls.

### `airui.network wireless_set`

Updates fields on an existing wireless UCI section.

Required:

```text
section
at least one configurable field
```

Example:

```sh
ubus call airui.network wireless_set '{
  "section": "wlan1",
  "ssid": "AirUI-Test",
  "encryption": "psk2",
  "key": "12345678",
  "disabled": false
}'
```

Dry run example:

```sh
ubus call airui.network wireless_set '{
  "section": "wlan1",
  "ssid": "AirUI-Test",
  "dry_run": true
}'
```

Success response data:

```json
{
  "operation": "set",
  "section": "wlan1",
  "dry_run": false,
  "changed": true,
  "uci_action": {},
  "uci_commit": {},
  "wireless_reload": {}
}
```

### `airui.network wireless_add`

Adds a new wireless UCI section.

Defaults:

```text
type = wifi-iface
section = generated by UCI if omitted
```

For `wifi-iface`, `device` is required.

Example:

```sh
ubus call airui.network wireless_add '{
  "section": "airui_guest",
  "type": "wifi-iface",
  "device": "radio0",
  "mode": "ap",
  "network": "lan",
  "ssid": "AirUI Guest",
  "encryption": "psk2",
  "key": "12345678",
  "disabled": true
}'
```

Dry run example:

```sh
ubus call airui.network wireless_add '{
  "section": "airui_guest",
  "type": "wifi-iface",
  "device": "radio0",
  "mode": "ap",
  "ssid": "AirUI Guest",
  "dry_run": true
}'
```

Success response data:

```json
{
  "operation": "add",
  "section": "airui_guest",
  "dry_run": false,
  "changed": true,
  "uci_action": {},
  "uci_commit": {},
  "wireless_reload": {}
}
```

### `airui.network wireless_delete`

Deletes a wireless UCI section.

Required:

```text
section
```

Example:

```sh
ubus call airui.network wireless_delete '{
  "section": "airui_guest"
}'
```

Dry run example:

```sh
ubus call airui.network wireless_delete '{
  "section": "airui_guest",
  "dry_run": true
}'
```

Success response data:

```json
{
  "operation": "delete",
  "section": "airui_guest",
  "dry_run": false,
  "changed": true,
  "uci_action": {},
  "uci_commit": {},
  "wireless_reload": {}
}
```

## Current UI Integration Contract

The frontend should use `airui.system capabilities` to discover the API surface,
then use `airui.network wireless_config` as the initial wireless page load.

Recommended UI workflow:

1. Call `airui.system health`.
2. Call `airui.system capabilities`.
3. Call `airui.network wireless_config`.
4. Render radios and SSIDs from `data.uci` and `data.runtime`.
5. For edit forms, submit only changed fields to `wireless_set`.
6. For new SSIDs, submit to `wireless_add`.
7. For delete actions, submit to `wireless_delete`.
8. Use `dry_run: true` before dangerous changes if the UI supports preview.
9. After a successful non-dry-run write, reload `wireless_config`.

The UI should treat `ok: false` as a handled API failure and display the first
entry from `errors`.

## Known Limitations

- No rollback transaction exists yet. If `uci set/add/delete` succeeds but
  `commit` or `network reload` fails, the API reports an error but does not
  automatically revert.
- `dry_run` validates arguments but does not ask UCI or netifd to validate the
  final resulting config.
- The add response reports the requested section name or an empty string. It
  does not yet extract the generated anonymous UCI section name when `section`
  is omitted.
- There is no section existence check before set/delete.
- There is no encryption-specific key validation.
- There is no conflict check for duplicate SSIDs or invalid radio/device
  combinations.
- There is no authorization layer in `airuid`; access currently depends on the
  caller's UBus permissions.
- Runtime status is passed through mostly raw from `network.wireless status`.
  It is not normalized into UI-specific radio/VIF models yet.
- Most AirUI domains are placeholders.
- No unit-test harness exists for the AirUI manager yet.

## Recommended Further Implementation Phases

### Phase 1: Harden Wireless API

Goal: make wireless add/edit/delete reliable enough for production UI use.

Tasks:

- add section existence checks using `uci get`;
- extract generated section name from `uci add` response;
- add encryption/key validation rules;
- validate `device` against existing wireless radios;
- validate `network` against existing network interfaces;
- add optional `apply: false` support for staged edits;
- add `airui.system apply_status`;
- add rollback handling for commit/reload failures;
- return warnings for risky but accepted configs;
- normalize `wireless_config` into `radios[]` and `interfaces[]` while keeping
  raw backend payload under `raw`;
- add tests for validation and response envelopes.

Suggested normalized response:

```json
{
  "radios": [
    {
      "section": "radio0",
      "band": "2g",
      "channel": "auto",
      "htmode": "HE20",
      "disabled": false,
      "runtime": {}
    }
  ],
  "interfaces": [
    {
      "section": "wlan1",
      "device": "radio0",
      "mode": "ap",
      "ssid": "AIR-2G",
      "network": "lan",
      "encryption": "psk2",
      "disabled": false,
      "runtime": {}
    }
  ],
  "raw": {
    "uci": {},
    "runtime": {}
  }
}
```

### Phase 2: LAN/WAN Config

Goal: implement the `airui.network lanwan_config` and `lanwan_set` methods.

Backend sources:

```text
uci network
ubus call network.interface dump
ubus call network.device status
```

Supported UI operations:

- read LAN address, netmask, gateway, DNS, DHCP mode;
- read WAN protocol and link state;
- edit LAN static IP and DHCP server basics;
- edit WAN DHCP/static/PPPoE basics;
- commit `network` and reload through default OpenWrt services;
- return warnings for management-IP changes.

Important safety behavior:

- use `dry_run` before LAN IP changes;
- support delayed apply with confirmation;
- provide rollback if the UI does not confirm after a timeout.

### Phase 3: Device Status API

Goal: implement `airui.status summary`, `clients`, and `statistics`.

Backend sources:

```text
netstatsd UBus methods
stamond UBus methods
network.wireless status
/proc and /sys data through structured helpers
```

Methods:

```text
airui.status summary
airui.status clients
airui.status statistics
```

Expected response domains:

- device uptime;
- CPU and memory;
- radio state;
- interface traffic counters;
- connected clients;
- signal/RSSI where available;
- firmware and board info.

### Phase 4: Controller Mode And Cloud State

Goal: make AirUI aware of cloud/controller connectivity without coupling the UI
to `cgwd` internals.

Method:

```text
airui.mode controller_status
```

Data:

- registered/unregistered;
- controller URL or tenant metadata if safe to expose;
- MQTT/WS connected state;
- last cloud error;
- last successful heartbeat;
- local-only mode state.

Longer-term operations:

- enable local-only mode;
- reset cloud registration;
- trigger reconnect;
- show pending cloud commands.

### Phase 5: Security And ACL Surface

Goal: implement `airui.security rules` and later controlled mutation APIs.

Backend sources:

```text
acld
firewall UCI
network config
policy/application visibility data
```

Initial read-only response:

- ACL enabled state;
- policy counts;
- blocked/allowed clients;
- rule summary;
- last enforcement update.

Mutation methods should be added only after typed contracts and rollback are in
place.

### Phase 6: Maintenance API

Goal: implement safe device operations.

Methods:

```text
airui.maintenance device_management_get
airui.maintenance reboot
```

Future methods:

```text
firmware_check
firmware_upload_prepare
firmware_upgrade
factory_reset
backup_config
restore_config
log_bundle
```

Rules:

- destructive operations require explicit confirmation fields;
- long-running operations should return job IDs;
- progress should be exposed through `apply_status` or a future `jobs` API;
- firmware operations must validate image metadata before sysupgrade.

### Phase 7: Shared Libraries

Goal: move repeated plumbing out of `airuid` before the API surface grows.

Candidates:

```text
libairresponse  common response envelope helpers
libairubus      UBus invoke/register/parse helpers
libairuci       UCI transaction helpers and rollback
libairapply     apply jobs, confirm/rollback, reload orchestration
libairplatform  radio/device/platform abstraction
```

This should happen incrementally. The current `airuid` helper files can become
the seed for these libraries once at least two managers need the same behavior.

### Phase 8: Tests And Board Validation

Goal: prevent API regressions while the UI starts depending on AirUI.

Local tests:

- response envelope builder tests;
- wireless argument validation tests;
- UBus result parser tests;
- normalized model builder tests.

Board tests:

- `ubus list airui.*`;
- health and capabilities;
- wireless config read;
- wireless add disabled test SSID;
- wireless set test SSID;
- wireless delete test SSID;
- verify radios remain up after reload;
- verify package reinstall starts `airuid`.

Suggested manual smoke script:

```sh
ubus call airui.system health
ubus call airui.system capabilities
ubus call airui.network wireless_config
ubus call airui.network wireless_add '{
  "section":"airui_test",
  "type":"wifi-iface",
  "device":"radio0",
  "mode":"ap",
  "network":"lan",
  "ssid":"AirUI Test",
  "encryption":"psk2",
  "key":"12345678",
  "disabled":true
}'
ubus call airui.network wireless_set '{
  "section":"airui_test",
  "ssid":"AirUI Test Updated",
  "disabled":true
}'
ubus call airui.network wireless_delete '{"section":"airui_test"}'
```

## Prompt For UI Implementation

Use this prompt when asking an AI UI builder to integrate the current backend:

```text
Build the AirUI wireless settings page against the OpenWrt UBus facade exposed
by airuid.

Use these backend calls:
- ubus call airui.system health
- ubus call airui.system capabilities
- ubus call airui.network wireless_config
- ubus call airui.network wireless_set '{...}'
- ubus call airui.network wireless_add '{...}'
- ubus call airui.network wireless_delete '{...}'

All responses use this envelope:
{
  "ok": boolean,
  "data": object,
  "warnings": array,
  "errors": array,
  "meta": {
    "timestamp": number,
    "source": "live",
    "schema": 1
  }
}

On page load, call health, capabilities, and wireless_config. Render radios and
wireless interfaces from data.uci and data.runtime. If the backend later returns
normalized radios[] or interfaces[], prefer those and keep support for the raw
current response.

Implement edit, add, and delete flows:
- edit calls airui.network wireless_set
- add calls airui.network wireless_add
- delete calls airui.network wireless_delete

Supported fields:
section, disabled, ssid, encryption, key, network, channel, htmode, country,
device, mode, type, dry_run.

Use dry_run:true for validation before showing a final confirm action for add,
delete, or dangerous changes. After any successful non-dry-run change, reload
wireless_config. Show errors[0].message when ok is false. Do not call raw UCI
methods from the UI; use only airui.* methods.
```

## Definition Of Done For Full AirUI Manager

The AirUI manager can be considered complete when:

- all registered methods return real data or intentional policy errors;
- wireless and LAN/WAN writes support validation, commit, apply, and rollback;
- status APIs are normalized and stable for UI use;
- cloud/controller status is exposed without leaking cloud-internal contracts;
- security and maintenance methods are safe by default;
- every mutating method supports `dry_run`;
- every mutating method returns structured warnings/errors;
- board smoke tests are repeatable;
- UI never needs to call raw OpenWrt UBus methods directly.

