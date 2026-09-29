# `air-onbd` Phase 1 Shadow Implementation

## Status

Phase 1 source implementation is complete in AIROS. It is not deployed to an AP and does not control onboarding behavior.

## Implemented

- New event-driven C daemon: `/usr/sbin/air-onbd`
- Source: `packages/aircnms/src/managers/onbd/`
- Procd service: `/etc/init.d/aironbd`
- Ubus object: `air.onboarding`
- Methods: `status`, `diagnostics`
- Three independent axes: lifecycle, connectivity and configuration
- Conservative visible-state derivation
- Named UCI section: `aircnms.onboarding`
- One-time creation of missing defaults through libuci
- Atomic runtime state mirror: `/run/air-onbd/state.json`
- Read-only observation of `network.interface`, `cgwd`, `netconfd`, stored device ID and the legacy `online` flag
- Structured state-transition logs
- Host unit test for device-ID validation, enrolled inference and operational degradation

## Safety boundary

This release is shadow-only. It does not:

- start or retry registration
- change MQTT state
- change Wi-Fi, radio, VLAN, network or firewall configuration
- enable or disable default/recovery SSIDs
- control LEDs
- restart any daemon
- create configuration jobs
- apply or roll back configuration

The `probe_scope` diagnostic value is `shadow-v1-object-and-legacy-uci`. It prevents consumers from interpreting the initial observations as proof of DHCP, DNS, HTTPS or MQTT session health.

## Files added

- `packages/aircnms/src/managers/onbd/Makefile`
- `packages/aircnms/src/managers/onbd/inc/onbd.h`
- `packages/aircnms/src/managers/onbd/src/main.c`
- `packages/aircnms/src/managers/onbd/src/onbd_state.c`
- `packages/aircnms/src/managers/onbd/src/onbd_persist.c`
- `packages/aircnms/src/managers/onbd/src/onbd_observe.c`
- `packages/aircnms/src/managers/onbd/src/onbd_ubus.c`
- `packages/aircnms/files/aironbd`
- `packages/aircnms/tests/onbd/test_onbd_state.c`
- `packages/aircnms/tests/onbd/run.sh`

## Files changed

- `packages/aircnms/Makefile`: build/install `air-onbd` and `aironbd`
- `base-files/platform/mt7621/etc/config/aircnms`: default named onboarding section

## Verification

- Host state tests: PASS
- MT7621 direct cross-compile with `-Wall -Wextra -Werror`: PASS
- Produced executable type: 32-bit MIPS32r2, musl, dynamically linked
- Shell syntax for procd/test scripts: PASS
- Git whitespace validation: PASS

The OpenWrt top-level `package/aircnms/compile` target did not produce a `.built` stamp or IPK despite `CONFIG_PACKAGE_aircnms=y`. Direct use of the configured MT7621 compiler proves the new daemon compiles and links, but package/IPK generation remains a separate SDK build-system issue to resolve before board deployment.

## Next verification

Before advancing beyond shadow mode:

1. Resolve/reconfirm the SDK package target used by the established firmware build workflow.
2. Build the AirCNMS IPK or firmware image.
3. Install on a test AP.
4. Verify `ubus call air.onboarding status` and `diagnostics`.
5. Confirm `/etc/config/aircnms` identity and credentials are unchanged.
6. Confirm only the named onboarding section is added when absent.
7. Reboot and confirm state reconciliation.
8. Measure CPU, RSS, logs and UCI write count.

## Real-board validation — 2026-09-28

Target:

- board: MT7621 AirPro AP
- management address observed from serial: `192.168.1.3`
- serial: `/dev/ttyUSB0`, 115200 baud, no flow control
- daemon binary: MIPS32r2 musl build `/usr/sbin/air-onbd`
- mode: `shadow_mode=1`

Validation results:

- installation and procd enable/start: PASS
- `air.onboarding` ubus object: PASS
- `status` and `diagnostics` schemas: PASS
- observed state: `ENROLLED / ONLINE / NONE`, reason `LEGACY_ONLINE_TRUE`
- dependency probes (`ubus`, `network.interface`, cgwd, netconfd): PASS
- runtime mirror `/run/air-onbd/state.json`: PASS
- service restart and state reconciliation: PASS
- forced `SIGKILL` and procd respawn: PASS
- full AP reboot and boot reconciliation: PASS
- existing cgwd, netconfd, netstatsd, stamond, eventd and cmdexecd processes healthy after reboot: PASS
- cloud MQTT PUBACK traffic after reboot: PASS
- wireless UCI snapshot before/after install and reboot: identical (`755a76c00bb28b2f8fd1be4831e52163`)
- Wi-Fi/network mutation by `air-onbd`: none observed
- footprint after reboot: approximately 1.5 MiB RSS, 2.8 MiB virtual size, one thread

Safety artifacts on the board:

- `/root/air-onbd-backup/aircnms.pre-air-onbd`
- `/root/air-onbd-backup/wireless.pre-air-onbd`
- `/root/air-onbd-backup/ubus.pre-air-onbd`
- `/root/air-onbd-backup/processes.pre-air-onbd`

The real-board portion of Gate S passes. Promotion out of shadow mode remains forbidden. The remaining Gate S limitation is reproducible package-level output through the OpenWrt top-level `package/aircnms/compile` target; direct toolchain compilation and runtime validation pass, but the package target currently produces no new IPK/build stamp and must be corrected before Gate S is formally closed.

## Gate S closure — 2026-09-28

The remaining package and bounded-runtime checks passed:

- clean SDK command: `make package/feeds/aircnms/clean V=s`
- clean SDK command: `make package/feeds/aircnms/compile -j4 V=s`
- package output: `bin/packages/mipsel_24kc/aircnms/aircnms_3_mipsel_24kc.ipk`
- package SHA-256 for this build: `ee8b08a9897c17d0d3828c13fc62b41320447efcfb0e87ec4477d4d2ae686d78`
- `.built` stamp recreated by the clean build
- IPK contains executable `./usr/sbin/air-onbd`
- IPK contains executable `./etc/init.d/aironbd`
- packaged daemon verified as ELF32, little-endian MIPS
- 60-second steady-state sampling: PID stable, RSS 1536 KiB, virtual size 2864 KiB across all seven samples
- `/etc/config/aircnms` content and metadata remained unchanged during steady state
- final derived state remained `ENROLLED / ONLINE / NONE`

Gate S is complete for the Phase 1 shadow coordinator. `shadow_mode=1` remains mandatory. Phase 2 typed cgwd-contract work may begin, but no production registration ownership is transferred to `air-onbd` by this gate.
