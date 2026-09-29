# Air Onboarding Specification Completion Tracker

Source: `Docs/AP_Onboarding.docx`, Technical Flow Specification V2.

## Release rule

A requirement is complete only after host tests, an MT7621 package build, physical-board validation, restart validation, and documented evidence pass. Cloud MQTT status payload compatibility must remain unchanged.

## Work increments

| Increment | Scope | State |
|---|---|---|
| A | Registration, credential persistence, MQTT integration | Complete |
| B | Shadow coordinator and local ubus status | Complete |
| C | Durable netconfd jobs and authoritative cloud revisions | Complete |
| D | Link, address, route, DNS, Internet and cloud probes | Complete |
| E | Structured cgwd and netconfd event consumption | Complete |
| F | Atomic owned-artifact snapshot and explicit recovery | Pending |
| G | Recovery SSID and fallback management IP ownership | Complete |
| H | Verified durable OPERATIONAL transition | Pending |
| I | Board-specific LED renderer and failure matrix | Pending |
| J | Factory-reset, outage, restart and power-loss matrix | Pending |

## Current safety boundary

Interrupted configuration application is fail-closed: netconfd persists `FAILED_NEEDS_ROLLBACK`, reports `recovery_required=true`, and rejects later configuration. Automatic rollback is not claimed until increment F passes power-loss testing.

## Increment D evidence

- Bounded nonblocking Internet probe and local carrier, address, route and DNS checks: PASS.
- MT7621 package build and physical-board validation: PASS.
- Board reported all five measured network facts true.

## Increment E evidence

- `air.cgwd.mqtt`, `air.cgwd.registration`, and `air.netconfd.job` subscriptions registered: PASS.
- Synthetic disconnect changed state immediately to `MQTT_DISCONNECTED/TEST_OFF`: PASS.
- Synthetic reconnect and revision 77 `APPLIED` job updated the corresponding axes: PASS.
- Daemon restart discarded synthetic runtime-only state and reconciled to durable state: PASS.
- Cloud MQTT status topic and payload behavior unchanged.

## Approach 4 Phase 1 closure

Status: COMPLETE on MT7621 canary.

- C coordinator, orthogonal state axes and ubus status/diagnostics: PASS.
- Periodic reconciliation plus `network.interface`, cgwd and netconfd event observation: PASS.
- LED policy removed from the legacy script; renderer consumes `air.onboarding.visible_state`: PASS.
- Board-specific system/wlan2g/wlan5g mapping: PASS with hardware color approximation.
- Package build, install, daemon restart and live diagnostics: PASS.
- Production cloud status payload/topic semantics: unchanged.

Phase 2 remains gated until fallback access is implemented and tested without disrupting the active management path.

## MT7621 physical LED validation

| Requested output | Physical observation | Result |
|---|---|---|
| Red | Red | PASS |
| Green | Green | PASS |
| Blue | Blue | PASS |
| Amber approximation | Lime-yellow with red and green active | PASS as documented approximation |
| White approximation | White with all three active | PASS |
| Slow red blink | Correct | PASS |
| Fast red blink | Correct using kernel LED timer at 250 ms on/off | PASS |
| Red/blue alternating | Correct | PASS |

The board has three binary LED channels (`system`, `wlan2g`, `wlan5g`, maximum brightness 1). It is not a single RGB LED, so combined colors are physical multi-LED approximations. The kernel timer trigger is required for reliable sub-second blinking; fractional BusyBox `sleep` is not suitable.


## Phase 2 recovery access completion

Implemented and validated on MT7621 AP `192.168.1.3` with `shadow_mode=1` as the default runtime guard.

Completed items:

- DHCP acquisition timeout classification: `DHCP_WAIT` becomes `DHCP_FAILED` after bounded wait/retry counters.
- Gateway reachability probe: default gateway is parsed from `/proc/net/route` and probed with bounded ping.
- DNS resolution probe: configured nameserver is not enough; cloud host must resolve with `getaddrinfo()`.
- HTTPS cloud probe: `https://<cloud-host>/health` is checked with libcurl certificate and hostname validation enabled.
- Internet and cloud failures are classified separately: `INTERNET_UNREACHABLE` vs `CLOUD_UNREACHABLE`.
- Dedicated fallback network: `airrecovery`, static `192.168.4.1/24`.
- DHCP is scoped only to `airrecovery`.
- Recovery SSIDs are generated as `AirPro-2G-{last 6 MAC}` and `AirPro-5G-{last 6 MAC}`.
- State-driven fallback enable/disable is wired through `air_onbd_recovery.sh`; in shadow mode it records intent only.
- Management addressing is preserved: AP test confirmed `network.lan` unchanged after enable/disable.

AP evidence, 2026-09-29:

- `ubus call air.onboarding diagnostics`: `probe_scope=measured-network-v3-gateway-dns-https`, `gateway_reachable=true`, `dns_resolved=true`, `cloud_reachable=true`, `fallback_active=false`.
- Controlled helper test created then disabled `wireless.aironbd2g` and `wireless.aironbd5g`; both ended with `disabled=1`.
- Recovery SSID names observed: `AirPro-2G-248BEA`, `AirPro-5G-248BEA`.
- `network.lan` before/after comparison: unchanged.

Release boundary:

- Real state-driven mutation remains protected by `shadow_mode=1`.
- Full destructive branch testing by physically breaking link/DHCP/gateway/DNS/cloud and rebooting in each recovery state is still a fleet-release acceptance activity.

## Deferred production policy — operational AP recovery

Decision: do not automatically move an already `OPERATIONAL` AP into `RECOVERY` for now.

Reason: real cloud configuration apply can briefly restart Wi-Fi/network, renew DHCP, remove the default route, or disconnect MQTT. Treating those short windows as recovery conditions can disturb an otherwise healthy AP.

Current intended behavior for production testing:

- Fresh or never-operational APs may use local fallback/recovery access during onboarding failures.
- APs that have reached `OPERATIONAL` must stay `OPERATIONAL` or `OPERATIONAL_DEGRADED` during WAN, DNS, Internet, cloud, MQTT, or config-apply interruptions.
- Recovery access for an operational AP should require explicit operator action until the long-duration reconnect design below is implemented.
- Recovery helpers must not overwrite cloud-managed SSIDs or destroy the WAN uplink on an operational AP.

Future fix:

- Add a long reconnect window before operational recovery, for example 5-10 minutes of sustained failure.
- Keep retrying WAN/DHCP/default-route/DNS/Internet/cloud/MQTT checks at a controlled interval while degraded.
- Enable recovery only after repeated sustained failure, or explicit operator request.
- Exit recovery only after multiple consecutive healthy checks.
- Keep dedicated recovery SSID/interface sections separate from cloud-managed VIFs.

Acceptance before enabling automatic operational recovery:

1. Config apply/reload does not trigger recovery.
2. DHCP renewal does not trigger recovery.
3. Short gateway/DNS/cloud/MQTT outage remains degraded only.
4. Sustained outage follows the documented timer and retry policy.
5. WAN uplink remains intact when operational recovery access is enabled.
6. Cloud SSIDs are not overwritten by recovery SSIDs.
