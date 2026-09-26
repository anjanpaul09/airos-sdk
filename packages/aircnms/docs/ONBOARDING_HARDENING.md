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

## Runtime ubus acknowledgement

`netconfd.set.cgwd.conf` validates the declared and actual payload sizes, allocates and
queues an owned copy, and immediately returns one of:

```json
{"accepted":true,"status":"QUEUED","message":"configuration queued","queueDepth":1}
```

```json
{"accepted":false,"status":"REJECTED","message":"invalid payload size","queueDepth":0}
```

This acknowledgement means the local request is safely queued. It does not claim that
the cloud has received an application acknowledgement. Actual cloud config revision and
APPLIED/FAILED reporting remain a separate end-to-end protocol.

## Production credential reconciliation (2026-09-26)

For serial `AIR587BE9248BEA` / device ID `1749368346`, the shared broker role contained
eight historical client credentials. The credential currently stored on and used by the AP
was identified by exact username and preserved. Seven superseded client rows and their
client-role/group associations were deleted in one assertion-guarded PostgreSQL transaction.
The shared role and all seven ACL rows were preserved.

Evidence and rollback exports:

- VM: `/opt/airpro-cloud/credential-revocation-20260926T063117Z`
- Off-host verified copy: `/tmp/airpro-revocation-copy/credential-revocation-20260926T063117Z`

Post-revocation, `air-cgwd` was restarted to force fresh authentication. It connected with
zero authentication errors, retained device ID `1749368346`, became online, and made no
registration request.
