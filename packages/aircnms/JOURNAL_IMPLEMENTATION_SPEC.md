# aircnms configuration journal and recovery specification

Status: proposed v1 format and protocol, 2026-09-07. Not implemented or power-cut-qualified. Companion: [overview](ARCHITECTURE_OVERVIEW.md), [identity spec](IDENTITY_IMPLEMENTATION_SPEC.md).

## 1. Scope and gates

`netconfd` is the single writer of a generation-based configuration journal. A generation is a complete metadata checkpoint referencing immutable artifact blobs; publishing `HEAD` selects the only authoritative generation. No append-log replay or guessing the newest filename.

Approve the format/protocol and recovery matrix before Phase 2 mutation implementation. Before the first mutation ships, run the full boundary fault suite on each supported filesystem/board. Unverified directory-fsync or flash persistence behavior blocks that target. Phase 1 isolated reads need no configuration journal, but must not accidentally mutate state.

This spec covers configuration operations and coordinated lease/expiry records. Maintenance installation has its own durable job protocol in `cmdexecd`; the cross-owner recovery handshake is a prerequisite before enabling upgrade/reset. This journal alone does not make firmware installation atomic.

## 2. Layout and encoding

Proposed persistent root: `/etc/airpro/state/netconfd/`, on the qualified persistent writable filesystem, never `/tmp`. Directory mode 0700, files 0600, owned by the service's privileged owner. No symlink following; descriptor-relative operations validate generated filenames, file type and ownership.

```text
netconfd/
  HEAD                         # authoritative generation selector
  generations/
    00000000000000000001.json   # immutable complete metadata generation
    .<random>.tmp              # unpublished temporary, never authoritative
  blobs/
    <sha256>.bin                # immutable original artifact bytes
    .<random>.tmp
  .HEAD.<random>.tmp
```

`HEAD` is exactly an ASCII line: `AIRJ1 <20-digit-generation> <64-lowercase-hex-sha256>\n`. Digest covers exact generation-file bytes. Generation JSON is UTF-8 without BOM, rejects duplicate keys, and uses schema-defined integer/string types. Integrity is corruption detection, not protection from malicious root rewriting both files. Unknown major format or corrupt/missing `HEAD` on an initialized installation enters recovery-required; never auto-select a different generation.

Mandatory generation fields:

| Field | Meaning |
| --- | --- |
| `format_major`, `format_minor` | Storage format, independent of wire/ABI versions; initial 1/0 |
| `generation`, `previous_generation` | Decimal strings; strictly increasing, no wrap/reuse |
| `committed_revision`, `confirmed_manifest` | Last confirmed resource representation and revision |
| `active_operation` | Null or complete operation described below |
| `terminal_records` | Bounded outcomes and idempotency scopes, including retention metadata |
| `maintenance_lease` | Null or coordinated owner/job reference and grant/reconciliation state |
| `expiring_rules` | Owner-managed runtime intent records described in section 8 |
| `initialized`, `last_writer_boot_id` | Explicit provisioning state and writer boot identity |

An active operation includes operation/principal/epoch IDs, idempotency scope and canonical request hash, admission revision, all nine-state lifecycle values, previous and candidate manifests, ordered plan, current step index, `step_phase` (`before` or `after`), recorded outcomes, confirmation verifier/binding/deadline metadata where applicable, and reserved capacity. Do not store authentication bearers.

A manifest maps approved logical resource IDs to artifact descriptors: managed absolute destination, blob hash, byte length, mode, owner/group, and `present` boolean. Absence is explicit for deletion/creation rollback. Destinations come from the owner inventory, never raw caller paths. Verify each blob before use. Capture all managed files and the normalized runtime restore plan; copying only `/etc/config/wireless` is not sufficient if vendor files or other resources change.

Serialize each complete generation once and hash those exact bytes. Readers need no canonical JSON reserialization. Canonical request hashing for idempotency is a separately specified codec. No native structs or pointers appear on disk.

First initialization is an explicit installation/provisioning step with no mutation side effects. It captures and verifies the existing baseline, writes generation 1 and publishes HEAD. Missing HEAD later is not interpreted as first boot automatically. Package upgrades preserve the root and require format compatibility.

## 3. Exact durable publication protocol

All operations occur under the service's exclusive journal/mutation coordination. Initial directory creation is followed by fsync of each created directory and its parent. Use this sequence for every new referenced blob, metadata generation, and HEAD update:

1. **B1 — temporary write:** create an unpredictable same-directory temporary with `O_CREAT|O_EXCL`, mode 0600, no symlink following. Write all bytes, handling partial writes/EINTR; set required metadata before synchronization.
2. **B2 — file synchronization:** `fsync(temp_fd)` and check success. Do not use close or stream flush as a durability substitute.
3. **B3 — immutable object publication:** rename the blob/generation temp to its final name, then `fsync(parent_directory_fd)`. Reuse a blob only after verifying its length/hash; never overwrite a conflicting existing immutable generation. Synchronize every new blob before publishing its referencing generation.
4. **B4 — HEAD temporary synchronization:** write the exact new HEAD line to a same-directory temp and `fsync` it. Until the next step the old HEAD remains authoritative.
5. **B5 — selector replacement:** rename the HEAD temp over HEAD. A crash before its parent-directory synchronization may expose old or new HEAD. Both referenced generations must already be complete and durable.
6. **B6 — selector durability:** `fsync(root_directory_fd)` and check success. Only now acknowledge durable admission or perform the next side effect justified by this checkpoint.

Any synchronization/rename error stops forward execution; do not acknowledge success. After B5/B6 ambiguity, read/validate the selector during controlled recovery and do not infer the result from the failed syscall alone. Keep both generations until resolved. Failure to durably record recovery-required is reported in memory/logs while writes remain disabled; never claim that a failed disk write persisted that state.

Every external step has a durable `before` checkpoint, then the effect, then an `after` checkpoint using B1–B6 again. Crash after effect but before `after` publication is explicitly ambiguous: read back/reapply idempotently as specified, or restore the last confirmed state. A plan with neither safe readback nor compensation is not admitted as a recoverable configuration apply.

Final success updates state, committed revision, confirmed manifest, terminal/idempotency result and consumed-confirmation marker **in one generation**. There is no separate revision file to race with it. A successful OS write/reload alone never finalizes the journal.

## 4. Limits and retention

Initial proposed profile limits, to be measured and approved per target: 4 MiB total journal allocation; at most 256 KiB per generation file; 128 retained terminal records; 512 KiB per configuration snapshot, 64 artifacts per snapshot, 128 plan steps; one active mutating operation. Reject oversize candidates before admission. These are ceilings, not assertions of available board flash.

Admission reserves enough free space for previous/candidate blobs, active/current and next complete generation plus one previous generation, and terminal/rollback publication. Reserve for the worst allowed serialized record size, not average size. Reject `busy`/storage-unavailable when reserve cannot be met. A filesystem shared with other writers can still fill afterward; qualification must exercise that failure and recovery behavior.

Retain terminal result/idempotency records for at least 24 hours of confirmed running time, capped by the 128-record capacity. Persist conservative age checkpoints during hourly housekeeping and ordinary commits; after restart, do not count unknown downtime toward expiry. A trusted clock may be added later but is not required for safety. If all record slots are unexpired, reject new admission instead of silently shrinking the retry guarantee. Reserved completion slots cannot be consumed by telemetry.

Never evict active, recovery-required, lease, or last-confirmed references to make room. No journal progress write per telemetry event. Metadata generations replace the replay log and are reclaimed under section 7, rather than rotated while still referenced.

## 5. Recovery matrix: lifecycle state × publication boundary

For every checkpoint write, test all six crash boundaries below. `P` means recover using the prior durable generation's state. `N` means recover using the newly selected generation's state. The state table in section 6 defines that recovery action; the table product covers all 54 state/boundary combinations. Also test each platform step before effect, during effect, and after effect before its next checkpoint.

| State being published | B1 temp bytes | B2 temp fsync | B3 generation/blobs durable | B4 HEAD temp durable | B5 HEAD rename, root not synced | B6 root synced |
| --- | --- | --- | --- | --- | --- | --- |
| queued | P | P | P | P | P or N, selected valid HEAD | N |
| applying | P | P | P | P | P or N, selected valid HEAD | N |
| verifying | P | P | P | P | P or N, selected valid HEAD | N |
| awaiting_confirmation | P | P | P | P | P or N, selected valid HEAD | N |
| succeeded | P | P | P | P | P or N, selected valid HEAD | N |
| rolling_back | P | P | P | P | P or N, selected valid HEAD | N |
| rolled_back | P | P | P | P | P or N, selected valid HEAD | N |
| failed | P | P | P | P | P or N, selected valid HEAD | N |
| recovery_required | P | P | P | P | P or N, selected valid HEAD | N |

At B1–B4, unpublished generations are garbage, not replay candidates. At B5, a missing/corrupt selector or missing referenced data is recovery-required, not permission to guess. At B6, loss of the newly selected complete generation on reboot is a failed filesystem durability qualification. For first initialization, P means uninitialized; only explicit provisioning may retry baseline initialization.

## 6. Recovery action by selected state

| Selected state | Startup action | Write readiness |
| --- | --- | --- |
| queued | No side effects were authorized. Mark failed with interrupted-before-execution result using a durable generation; retain idempotency mapping | After publication and baseline checks |
| applying | Treat the current `before`/`after` marker as possibly having effects. Restore last confirmed files/runtime, verify, publish rolled_back | After verified durable rollback |
| verifying | Candidate not confirmed. Restore/verify last confirmed state and publish rolled_back | After verified durable rollback |
| awaiting_confirmation | Never revive token/timer after owner restart. Restore/verify last confirmed state and publish rolled_back | After verified durable rollback |
| succeeded | Preserve committed revision/result; reconcile runtime to confirmed intent. A discrepancy is drift/recovery, not a reason to replay the original action | After runtime reconciliation |
| rolling_back | Continue idempotent restore of last confirmed manifest and runtime; verify then publish rolled_back | After verified durable rollback |
| rolled_back | Verify/reconcile last confirmed baseline; preserve failed-change outcome | After reconciliation |
| failed | Permitted only when no effects remain or no effects began; verify baseline. Inconsistent metadata/effects becomes recovery-required | After verification |
| recovery_required | Preserve evidence, expose diagnostic reads, permit only authorized restore/adopt procedure | Normal writes disabled |

Any restore/verification failure transitions to recovery-required if it can be persisted. Restart recovery acquires exclusivity before touching runtime. `previous_generation` is diagnostic/GC metadata, not an automatic fallback when HEAD or confirmed data is corrupt.

Special boundary cases: admission reply lost after B6 is recoverable by idempotency; a crash during final succeeded B5 may yield rollback or durable success depending on selected HEAD, and the client must query; a crash after confirmed B6 returns succeeded even if no reply was delivered. Timers never override a selected durable success.

## 7. Crash-safe garbage collection

Run GC at startup after validation/recovery, hourly while idle, and before admission under storage pressure. Serialize the mark/sweep with publication so it cannot delete a just-created reference. Do not run an independent unsynchronized sweeper.

1. Validate HEAD and build the live set: selected generation, one prior validated generation and all blobs referenced by either, including confirmed/active/lease/expiry data.
2. Expire eligible terminal records by publishing a new complete generation using B1–B6. Until it is durable, their records remain live. A previous retained generation can conservatively retain them longer.
3. Under the publication lock, delete older unreferenced generations, then unreferenced blobs and abandoned temp files; fsync affected directories. Never follow paths from untrusted filenames.
4. A crash during sweep leaves some garbage for the next pass; no selected generation references deleted data. Deletion-directory fsync failure may resurrect garbage after reboot, which is safe and reclaimed later. A malformed live reference stops GC and writes.

GC does not erase flash securely. Secret material can remain in flash pages or retained generations after logical deletion; see the identity spec's secrets-at-rest boundary. Format upgrades and reset need separate retention/erasure behavior, not ad hoc directory deletion.

## 8. Expiring application-policy intent

Treat `acld` intents as explicit ephemeral rules owned by `netconfd`, not as ordinary permanently committed policy or delayed rollback of the entire configuration. Records contain rule ID, principal/epoch, resource scope, payload digest, creation boot ID, monotonic expiry, and enforcement handle/ownership tag. Proposed TTL range: 1–300 seconds; caller renewal is a new authorized idempotent operation with current resource checks.

Before enabling a rule, journal the intent and `before` marker; after effect record its handle/result. Enforcing backends must support bounded expiry or safe removal on owner failure for this capability. Prefer a native enforcement timeout; if no way exists to meet expiry while netconfd is unavailable, advertise ephemeral enforcement as unsupported rather than promise a hard TTL using only a userspace timer.

A scheduled owner timer removes expired rules through the normal exclusive coordinator and journals the removal. Reads also mark elapsed rules expired and trigger reconciliation, but read-triggered cleanup is not the expiry mechanism. Cleanup has priority over new admission; native expiry must still bound effect during a held apply/confirmation slot. Verification treats native expiry as an expected state transition.

On owner restart/boot, conservatively remove all prior-boot ephemeral rules before write readiness, regardless of wall-clock validity. On uncertain expiry within the same boot, remove rather than extend. Configuration rollback/restore must not recreate expired or prior-boot rules from an old snapshot: the durable baseline excludes ephemeral enforcement, and reconciliation applies only currently valid explicit entries. An `acld` crash cannot renew rules. Failure to remove is degraded/recovery-required and tested against the backend's timeout guarantee.

## 9. Required implementation evidence

Implement host format/parser limits, integrity checks, all 54 matrix cases, platform-step fault points, GC interruption, capacity exhaustion, missing/corrupt selector/blob, duplicate admission, confirmation reply loss, and ephemeral-rule expiry/restart tests. Then power-cut test B1–B6 on the real filesystem and driver restore plan, including external storage pressure.

Maintain a machine-readable test manifest with `(state, checkpoint, selected_head, platform_effect_position, expected_outcome)` for each case; the table is not a substitute for executed evidence. Gate status remains **open (not passed)** until implementation and target results exist.
