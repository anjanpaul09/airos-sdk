# air-netconfd configuration hardening

## Scope

Release-candidate validation was performed on MT7621 AP `AIR587BE9248BEA` against the production cloud contract. Captive portal was explicitly excluded. The tested daemon binary SHA-256 is `f35e5287381ded3c4eb765734eacda168320ac72004357dd13a5e4dc254a6cf9`; the package SHA-256 is `bb860c5deda694079cca372c7ca5f16f4bc96c6e992151f0a7cbaaf0c6988695`.

## Behavioral changes

- Strict, bounded schema validation precedes all UCI, network, firewall, hostapd, and traffic-control mutations.
- Malformed and poison messages are removed after one attempt and logged as `QUEUE_DROP`.
- VIF updates are committed as one desired-state batch with one `wifi reload`.
- Success requires the expected Linux interfaces to exist or be absent after netifd/hostapd convergence.
- Disabled desired-state records remove stale SSIDs; open encryption removes stale keys.
- SSID and key buffers accept the protocol maxima safely (32-byte SSID, 64 hex PSK).
- UCI, reload, NAT, radio, VIF, ACL, and rate-limit failures propagate to the queue result.
- NAT uses the supplied netmask instead of forcing `/24`.
- Cloud radio compatibility is retained: historical `disabled=true` means radio active and maps to UCI `disabled=0`.
- MT7621 firmware now selects `hostapd-openssl`, which supplies SAE/OWE support. Pure WPA3 Personal writes `encryption=sae` with required PMF (`ieee80211w=2`); WPA2/WPA3 transition mode writes `sae-mixed` with optional PMF (`ieee80211w=1`). Encryption changes reset PMF and open mode removes stale keys.
- WPA3 Enterprise remains accepted through the existing `wpa3` UCI mapping for a separate RADIUS validation pass; it was not claimed as end-to-end verified here.
- Config payload contents and credentials are no longer written wholesale to logs.

## Board verification

| Area | Evidence | Result |
|---|---|---|
| Invalid payloads | malformed JSON, length/key/encryption/VLAN/radio/schedule/RADIUS/channel/country/hwmode errors, duplicates, framing mismatch | PASS; no wireless mutation |
| Personal security | WPA2, WPA/WPA2 mixed, 64-hex PSK, open transition/key removal | PASS |
| Enterprise security | WPA2 Enterprise server, ports, and secret | PASS |
| WPA3 Personal | pure SAE and WPA2/WPA3 transition on spare wlan3; generated hostapd config and live BSS | PASS; `SAE`/PMF 2 and `WPA-PSK WPA-PSK-SHA256 SAE`/PMF 1 |
| WPA3 transitions | SAE → mixed → open; invalid short SAE key | PASS; PMF reset, stale key removed, rejection left UCI unchanged |
| WPA3 Enterprise | accepted by schema and mapped to `wpa3` | PENDING end-to-end RADIUS/client validation |
| SSID | 32-byte maximum and hidden mode | PASS |
| Schedule | enabled/disabled day entries and exact times | PASS |
| Desired state | disabling a stale VIF | PASS |
| Eight-VIF batch | wlan1/2 enabled, wlan3-8 disabled, one reload | PASS; queue processing about 4 seconds |
| Idempotent replay | same eight-VIF payload | PASS; identical UCI hash, about 5 seconds |
| Radio | both bands enabled, automatic channel, 25/30 dBm | PASS; both runtime radios up |
| ACL | device blacklist add/remove | PASS in hostapd runtime deny lists |
| Rate limit | unknown station and value above 10000 Mbps | PASS by `QUEUE_DROP` |
| VLAN | VLAN 123 on spare wlan3 | PASS; bridge/network/firewall and runtime VIF verified |
| NAT | `192.168.77.1/25` on spare wlan3 | PASS; supplied `255.255.255.128` persisted and runtime bridge created |
| Restart | netconfd restart and cloud agent restart | PASS |
| Retained cloud config | 4,871-byte payload; wlan1/2 live, wlan3-8 disabled | PASS; one `QUEUE_APPLIED` |
| Rollback | network/firewall/wireless/dhcp snapshot restore after disruptive tests | PASS |

## WPA3 board evidence (2026-09-27)

- Hostapd package: `hostapd-openssl 2024.09.15~5ace39b0-r2`; installed binary SHA-256 `b1592e47eb49b2b0e504d180b41f79bfa772bfac1856eea8d1776753fdbd83fe`.
- Netconfd candidate SHA-256: `fcb97dec73fb21984f635d0748ce10d492aafa7446579faf1c643fd519f9fbe8`.
- Board backup: `/tmp/wpa3-hostapd-backup-20260927T141206Z.tgz`, also copied off-device under `/tmp/airpro-wpa3-20260927T193817/board-backup/`; SHA-256 `c0b231f8d85c93d8204c4d4ed120b105b5d112016bc96e494363fbf7fa369179`.
- SDK `.config` backups: `/tmp/airpro-wpa3-20260927T193817/openwrt.config.before` and `openwrt.config.sae`.
- Pure SAE and transition-mode BSSs reached hostapd `state=ENABLED` on `phy0-ap1`. Production wireless configuration was restored, wlan3 disabled, both `WifiTech` radios returned `up`, and `air-cgwd`/`air-netconfd` were running after the test.
- A package install alone is insufficient for a live upgrade: restart `/etc/init.d/wpad` before testing so the jailed hostapd process loads the new executable.

## Known constraints

- The ubus call acknowledges queue admission, not completion. `QUEUE_APPLIED`/`QUEUE_DROP` are local operational evidence. A cloud-visible revisioned `APPLIED`/`FAILED` protocol remains separate work.
- A positive per-client rate-limit test requires an associated test station. Failure behavior for an unknown station and validation bounds are covered.
- ACL state is hostapd runtime state and is re-established from cloud desired state after restart; it is not persisted in UCI.
- VLAN and NAT operations restart network services and can briefly interrupt management traffic. The asynchronous queue prevents the ubus caller from blocking, but rollout monitoring must allow for reconvergence.
- The logging subsystem sometimes emits unrelated informational lines with `TRACEBACK` severity. This pre-existing formatting defect does not indicate a netconfd crash but should be corrected separately.
- WPA3 Enterprise association/authentication is not yet tested; support must remain canary-only until the RADIUS and client matrix passes.
- Captive portal was not tested or changed in this release candidate.

## Release procedure

1. Build from the synchronized AirCNMS source with `make package/aircnms/clean` and `make package/aircnms/compile -j4`.
2. Record binary and IPK SHA-256 values.
3. Upgrade one serial-accessible AP first.
4. Verify both radios and management connectivity, then apply a known desired state.
5. Require `QUEUE_APPLIED`, expected UCI values, and expected runtime interfaces.
6. Run a cloud retained-config replay and a reboot test before expanding the canary group.
7. Keep the previous IPK and configuration archive for rollback.
