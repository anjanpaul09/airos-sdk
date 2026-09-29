# `air-onbd` Phase 3 — netconfd job contract

## Status

The job ledger and its crash-safe metadata journal are implemented, cross-built, and validated on a real MT7621 AP. Applied job state survives a daemon restart without reapplying configuration. Phase 3 is not complete: caller-supplied revision semantics, cancellation, semantic normalization, and full retry/superseding policy remain gated work.

## Implemented contract

Configuration submission through `set.cgwd.conf` now returns:

- schema `air.netconfd.job.v1`
- stable process-local `job_id`
- local monotonic `revision`
- SHA-256 `config_hash`
- actual job `status`
- `duplicate` indication
- current queue depth

New methods:

```sh
ubus call netconfd status
ubus call netconfd job.status '{"job_id":"cfg-..."}'
```

New event:

```text
air.netconfd.job
```

Implemented states in this slice:

```text
QUEUED → APPLYING → APPLIED
                  ↘ FAILED
QUEUED → SUPERSEDED  (queue eviction)
```

The ledger uses compare-and-set state transitions. A stale or repeated transition is rejected. The bounded 32-record ring never overwrites an active `QUEUED` or `APPLYING` job. Identical payload bytes coalesce to the existing record instead of entering the queue again.

## Crash-safe journal

The ledger persists metadata to `/etc/airpro/netconfd-jobs.json` using schema `air.netconfd.journal.v1`. Configuration payloads and secrets are never written to the journal.

Persistence uses a temporary file, file `fsync`, atomic `rename`, and parent-directory `fsync`. The final file is mode `0600`. A persistence failure makes `journal_healthy=false` and `ready=false`; netconfd therefore fails closed instead of claiming durable acceptance.

Boot reconciliation is deterministic:

- `APPLIED`, `FAILED`, and `SUPERSEDED` remain terminal.
- persisted `QUEUED` becomes `FAILED/PAYLOAD_LOST_AFTER_RESTART` because payload bytes are deliberately not journaled.
- persisted `APPLYING` becomes `FAILED/FAILED_NEEDS_ROLLBACK`; runtime state must be inspected before a retry.

`netconfd status` exposes both `ready` and `journal_healthy`.

## Files

- `src/managers/netconfd/inc/netconf_job.h`
- `src/managers/netconfd/src/netconf_job.c`
- `src/managers/netconfd/src/netconf_ubus_rx.c`
- `src/managers/netconfd/src/netconf_queue.c`
- `src/managers/netconfd/src/main.c`
- `tests/test_netconf_job.c`

## Verification

### Host

- SHA-256 generation: PASS
- duplicate submission coalescing: PASS
- ordered compare-and-set transitions: PASS
- stale transition rejection: PASS
- latest/status lookup: PASS
- sanitizer-enabled job-ledger test: PASS
- atomic journal persistence and reload: PASS
- terminal `APPLIED` preservation: PASS
- restart reconciliation for persisted `QUEUED` and `APPLYING`: PASS
- journal contains metadata only: PASS
- full onboarding unit runner: PASS
- clean MT7621 package build: PASS

### Target

- package SHA-256: `2902fde482f8f12111f111b9d9c97decb85bd4d5000634bee5d15afc54c82c2e`
- deployed `air-netconfd` SHA-256: `34fe47921f83c8df1c4993cbdadf98c5d1c52dd3d07ad2b74be1b771283fbe41`
- service running: PASS
- retained production desired-state job: `QUEUED → APPLYING → APPLIED`
- journal: 248 bytes, mode `0600`, schema `air.netconfd.journal.v1`
- before restart: `cfg-1-1`, revision 1, generation 3, `APPLIED`, hash `sha256:c6199ceaa426c86843044deb2cd3c82c6a6d6de195c20b81e379646bdf23db4d`
- after netconfd-only restart: same job ID, revision, generation, state, reason, and hash
- daemon PID changed from `26439` to `27813`; `ready=true`, `journal_healthy=true`
- cgwd remained `REGISTERED` and MQTT connected
- wireless and network UCI hashes were byte-for-byte unchanged across restart
- result: `RESTART_PERSISTENCE_PASS`

Rollback binary: `/root/air-onbd-backup/air-netconfd.phase3-jobs`.

## Deliberate limitations of this slice

- Revisions are local receipt revisions, not yet authoritative cloud revisions.
- Exact-byte hashes mean semantically equivalent JSON with different formatting is a different job.
- A failed duplicate remains failed and is not automatically retried.
- `job.cancel` is not exposed yet.
- ACL and rate-limit messages retain the legacy queue response and are not configuration jobs yet.
- Events are local ubus acknowledgements only; no cloud acknowledgement is sent.
- An interrupted `APPLYING` job is conservatively marked `FAILED_NEEDS_ROLLBACK`; automated runtime inspection and rollback are not implemented yet.

These limitations prevent Phase 3 sign-off. The next increment is explicit cloud revision conflict/staleness handling and a deterministic retry/rollback policy.

## Authoritative cloud revision increment

Implemented after the original job-ledger slice:

- A positive integer top-level `revision` in configuration JSON is treated as the authoritative cloud revision.
- Missing `revision` remains accepted only for initial-enrollment and legacy compatibility.
- Non-integer, zero, and negative revisions are rejected before queue admission.
- Same revision and identical bytes return the existing job (`duplicate=true`) without a second apply.
- Same revision with different bytes is rejected as a conflict.
- A revision below the highest durably accepted cloud revision is rejected as stale.
- A newer accepted revision marks older cloud-revision jobs that are still `QUEUED` as `SUPERSEDED` with reason `NEWER_CLOUD_REVISION`.
- The worker now discards a queued payload when its `QUEUED -> APPLYING` compare-and-set fails. Previously it logged the rejection but still called the configuration processor, which could apply superseded or otherwise invalid work.
- Job replies, status responses, and events include `cloud_revision` when present.

Deterministic retry rule: retry the same revision with the same payload to retrieve its existing outcome. A failed or superseded revision is not reapplied. Changed desired state requires a higher revision. This prevents ambiguous transport retries from duplicating configuration writes.

Verification:

- onboarding host suite: PASS
- revision duplicate/conflict/stale/newer-supersedes-older cases: PASS
- clean MT7621 `package/aircnms` cross-build: PASS
- target test pending because `192.168.1.11:3041` was unreachable (`No route to host`)

Remaining rollback gate: an interrupted `APPLYING` job is durably classified as `FAILED_NEEDS_ROLLBACK`, but automatic snapshot restoration and verification are not implemented. Fleet release must not claim automatic rollback until that recovery path passes power-loss tests on the board.

## Fail-closed interrupted-apply recovery

The daemon now treats an interrupted `APPLYING` job as an explicit recovery gate:

- On journal load, the job becomes `FAILED` with reason `FAILED_NEEDS_ROLLBACK`.
- `recovery_required=true` remains durable across later daemon restarts while that record exists.
- The status API reports `ready=false` and `recovery_required=true`.
- Both authoritative-revision and legacy configuration submissions are rejected before queue admission.
- No automatic restore is attempted. A reboot or daemon restart can occur after the underlying system accepted a configuration but before the job was marked `APPLIED`; blindly restoring at boot could therefore undo a valid configuration.

This is the safe release-candidate boundary until an owned-artifact snapshot/restore protocol exists. That protocol must atomically snapshot every configuration artifact touched by an apply, durably associate the snapshot with the job ID and cloud revision, restore through an explicit recovery operation, verify runtime and persistent state, and only then clear the recovery gate.

Verification:

- interrupted `APPLYING` reconciliation: PASS
- recovery gate survives a second journal reload: PASS
- revised and legacy submissions fail closed while recovery is required: PASS
- onboarding host suite: PASS
- clean MT7621 `package/aircnms` cross-build: PASS
