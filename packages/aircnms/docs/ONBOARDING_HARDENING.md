# AirCNMS onboarding hardening

This change makes AP enrollment validate-then-apply and removes shell-generated UCI writes.
It applies to `air-cgwd`; cloud-side idempotency remains authoritative.

## Invariants

- Reject malformed, duplicate-key, oversized, incomplete, or out-of-range registration responses.
- Verify TLS and HTTP 2xx, with connect, total, and low-speed timeouts.
- Accept the current cloud topic contract: `device`, `client`, `vif`, `event`, `websiteUsage`, `status`.
  The authorized `event` topic backs legacy `neighbor`, `config`, and `cmdr` fields.
- Apply initial network configuration before credential persistence.
- Replace and deduplicate the subscription list in one native libuci commit.
- Treat the cloud broker and port as authoritative; registration never declares connectivity online.
- MQTT connect/disconnect owns `online`; secrets and complete cloud payloads are not logged.
- A normal restart uses stored identity and does not call registration.

## Failure behavior

A failed HTTP request, invalid response, decryption error, rejected initial configuration, or failed
UCI commit leaves the previously committed identity and credentials intact. A missing local device ID
causes bounded enrollment retries. The supervisor may retry the daemon, but partial credentials must
never be committed.

## Verification

Run host crypto tests:

```sh
packages/aircnms/tests/run_onboarding_unit_tests.sh
```

Build with warnings as errors:

```sh
cd /home/airpro/projects/airpro/mtk/mt7621/sdk/openwrt
make package/aircnms/clean
make package/aircnms/compile -j4
```

Board acceptance checks:

1. Fresh/replay registration returns the original device identity and credential hashes.
2. UCI contains exactly 9 unique subscription topics.
3. Broker is the response endpoint and MQTT connects before `online=1`.
4. `/etc/config/wireless`, `network`, and `dhcp` remain consistent with accepted `configData`.
5. Restart causes zero registration requests, one logical subscription per topic, and telemetry resumes.
6. Logs contain no encrypted credential response, resource key, decrypted password, or full cloud payload.
7. Malformed response and config failure tests preserve the last committed identity.

## Known system-level follow-ups

- The current netconfd configuration method can exceed the regular 3-second MQTT command timeout.
  Initial enrollment uses 60 seconds, but runtime config needs asynchronous acknowledgement/revision handling.
- Broker records created by firmware predating cloud r3 are not revoked automatically. Revoke confirmed stale
  credentials using a controlled cloud-side reconciliation procedure.
- Load, power-loss-during-flash, broker outage, DNS outage, CA expiry, and cloud rollback tests belong in the
  release qualification matrix; a single physical AP cannot prove fleet scale.
