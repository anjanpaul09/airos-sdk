# AirCNMS Onboarding RC1

Release candidate: `aircnms-onboarding-rc1-20260927`

## Source identity

- AIROS branch: `feature/aircnms-airdpi-removal`
- Onboarding hardening commits:
  - `dc2c9c2` — Harden AirCNMS cloud onboarding
  - `1cf7ccb` — Acknowledge queued netconfd configurations
  - `4e31eeb` — Document broker credential reconciliation
- Package: `aircnms_3_mipsel_24kc.ipk`
- Package SHA256: `0c029b7644a0035a2fcdc73814fdb747608717d9715373bb251da6d4d3d21a36`

## Release scope

This candidate covers:

- device registration request and response validation;
- bounded HTTPS transport and TLS certificate verification;
- encrypted credential decoding and validation;
- atomic UCI persistence of cloud identity, credentials, and topics;
- stable device identity and credential reuse across daemon restarts;
- cloud-authoritative MQTT host and port;
- MQTT topic replacement and deduplication;
- current cloud topic compatibility through the `event` topic;
- MQTT online/offline ownership;
- queued ubus handoff from cgwd to netconfd;
- explicit `QUEUED` and `REJECTED` local ubus responses;
- removal of the known stale broker credential fork for the validation AP.

## Verification evidence

- Exact tracked source exported into the OpenWrt SDK feed.
- Clean `make package/aircnms/clean` and `make package/aircnms/compile -j4`: PASS.
- AES/decryption negative and positive unit cases: 10/10 PASS.
- Rebuilt IPK is byte-identical to the validated package SHA256 above.
- Rebuilt `air-cgwd` SHA256: `33a08be419c79e3db5d1b8b1c25b0bdf51aa1569152d29b57f24ad627e0ba951`.
- Rebuilt `air-netconfd` SHA256: `a52223cd83a04aee74200aa2916185a3b2637f600976ce53245e7ffa181ec663`.
- Both binary hashes match the physical MT7621 AP.
- Physical AP MQTT endpoint: `69.30.254.180:35930`.
- Physical AP maintains device ID `1749368346`, publishes telemetry, receives PUBACK, and remains online after cgwd restart.
- Registration is suppressed when valid stored credentials are present.
- Nine unique subscription topics are persisted without duplication.
- Valid retained configuration is accepted and queued without the former 3-second ubus timeout.
- Malformed or oversized local configuration requests are rejected.

## Acceptance boundary

`QUEUED` proves that netconfd validated, copied, and queued the configuration payload. It does not prove that every later UCI, Wi-Fi, VLAN, ACL, or service-reload operation succeeded.

Cloud-visible revision-based `APPLIED`/`FAILED` acknowledgement is deferred. Fleet rollout must treat configuration completion as eventually observed through resulting telemetry until that protocol exists.

Legacy configuration handlers outside the onboarding path still contain shell-command construction and unchecked string operations. They require a separate hardening project and are not certified by this onboarding RC.

## Rollout controls

1. Roll out to a small canary group first.
2. Preserve the previous IPK and device configuration before upgrade.
3. Verify binary hashes after installation.
4. Confirm daemon health, MQTT authentication, telemetry, stable identity, and unique topics.
5. Do not clear working credentials during an upgrade.
6. Stop rollout on credential rotation, repeated registration, MQTT authentication failure, crash loop, or unexpected network configuration change.

## Rollback

Reinstall the previously approved AirCNMS IPK, restart AirCNMS daemons, and confirm the existing UCI identity and credentials remain intact. Do not erase `/etc/config/aircnms` as part of an ordinary rollback.
