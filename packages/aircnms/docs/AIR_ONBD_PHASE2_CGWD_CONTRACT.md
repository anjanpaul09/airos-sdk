# `air-onbd` Phase 2 — cgwd typed contract

## Status

Implementation complete and validated on a real MT7621 AP for the enrolled-device path. Factory-state asynchronous registration remains a hardware acceptance item. Registration ownership has not moved to `air-onbd`.

## Implemented slice

`ubus call cgwd status` returns a versioned, credential-safe payload:

```json
{
  "schema": "air.cgwd.status.v1",
  "enrollment_state": "REGISTERED",
  "enrollment_state_code": 2,
  "registered": true,
  "mqtt_configured": true,
  "mqtt_connected": true,
  "device_id_present": true,
  "serial_present": true,
  "queue_depth": 0
}
```

The contract deliberately reports enrollment and MQTT state independently. It does not expose MQTT usernames/passwords, resource keys, broker addresses, topics, configuration payloads, complete device identifiers or serial numbers.

## Source changes

- `src/managers/cgwd/src/cgw_ubus.c`
  - added the read-only `status` method
  - added schema `air.cgwd.status.v1`
  - expanded the method table from six to seven entries

No registration, MQTT reconnect, retry, cancellation, persistence or cloud-response behavior changed in this slice.

## Verification — 2026-09-28

- AIROS source copied exactly to the OpenWrt package tree
- clean package build: PASS
- generated cgwd contains the schema and typed fields: PASS
- package output: `aircnms_3_mipsel_24kc.ipk`
- package SHA-256: `ee3709183845bae6c09cc720b2500b6338f82a198ab51f879d11dd097cdb58ac`
- prior board cgwd backed up at `/root/air-onbd-backup/air-cgwd.pre-phase2-status`
- cgwd-only restart: PASS
- `ubus call cgwd status`: PASS
- observed `REGISTERED`, MQTT configured and connected, queue depth zero
- MQTT reconnect, subscriptions, online publish and PUBACK: PASS
- `air-onbd` briefly observed the expected disconnect and returned to `ENROLLED/ONLINE`: PASS
- wireless UCI before/after cgwd replacement: identical

## Remaining Gate C work

1. Add registration attempt state with stable attempt IDs.
2. Parse and classify structured cloud responses into `SUCCESS`, `PENDING_CLAIM`, `UNKNOWN_DEVICE`, `MAC_MISMATCH`, `REJECTED`, `TEMPORARY_FAILURE`, `PERMANENT_FAILURE` and `CANCELLED`.
3. Add asynchronous `registration.start` and result events.
4. Ignore stale attempt completions.
5. Add bounded `registration.cancel` and `mqtt.reconnect` controls.
6. Emit versioned MQTT connectivity events.
7. Add exact-topic routing tests and response fixtures.
8. Prove credentials never appear in ubus replies, events or logs.
9. Validate unknown, pending, mismatch, timeout, malformed response, duplicate request, restart and existing-enrolled scenarios.

The board remains compatible with the current cloud and `air-onbd` remains in shadow mode.

## Typed registration-result classifier — 2026-09-28

Added:

- `inc/cgw_registration_result.h`
- `src/cgw_registration_result.c`
- `tests/test_cgw_registration_result.c`

`send_request()` now classifies transport and cloud outcomes before processing success credentials. The existing boolean API and successful enrollment processing remain compatible.

Classification behavior:

- transport errors, HTTP 429 and HTTP 5xx → `TEMPORARY_FAILURE`
- structured `PENDING_CLAIM`, `UNKNOWN_DEVICE`, `MAC_MISMATCH`, `REJECTED`, `CANCELLED`, `PERMANENT_FAILURE` → matching typed result
- HTTP 401/403 without a structured code → `REJECTED`
- malformed, incomplete, ambiguous duplicate-key, unexpected-code and other non-success responses → fail closed as `PERMANENT_FAILURE`
- current legacy HTTP 200 success → accepted only when strict UTF-8 JSON contains non-empty typed `deviceId`, `username`, `password`, `resourceKey` and object `configData`

Security properties:

- response bodies and credentials are not logged
- duplicate `code` or `status` decision keys fail closed
- trailing non-whitespace data is rejected
- marker strings inside error messages cannot create a false success
- malformed field types cannot create a false success

Verification:

- decrypt tests: 10/10 PASS
- registration classifier cases: PASS
- strict host build with ASan/UBSan: PASS
- clean MT7621 AirCNMS package build: PASS
- installed hardened cgwd on the AP with rollback copies retained
- existing enrolled state, MQTT connection, online publish and PUBACK: PASS
- `ubus call cgwd status`: PASS

This slice exposes typed results in logs and internal code only. Attempt IDs, asynchronous start/result events, cancellation and stale-result rejection remain the next Phase 2 increment.

## Registration attempt state core — 2026-09-28

Added:

- `inc/cgw_registration_attempt.h`
- `src/cgw_registration_attempt.c`
- `tests/test_cgw_registration_attempt.c`

Behavior:

- attempt IDs contain the kernel boot ID, a monotonic in-process generation and monotonic time
- only one attempt may be `RUNNING`
- concurrent starts reuse the same active attempt ID
- completion is compare-and-set on the active attempt ID
- stale, duplicate or post-cancellation completions are rejected
- cancellation is compare-and-set and produces `CANCELLED`
- the existing synchronous registration path now records start and typed completion
- an overlapping synchronous request is coalesced and does not issue a second cloud request

`ubus call cgwd status` now also returns:

```json
{
  "registration_attempt_state": "IDLE",
  "registration_attempt_id": "",
  "registration_result": "NONE",
  "registration_generation": 0
}
```

Verification:

- attempt state/concurrency/stale-result unit test: PASS
- existing decrypt and classifier suites: PASS
- clean MT7621 package build: PASS
- deployed cgwd-only build with rollback backup
- enrolled AP reports `IDLE/NONE`, proving no boot-time re-registration
- MQTT CONNACK, subscriptions, online publish and PUBACK: PASS
- wireless UCI unchanged

Limitations retained intentionally:

- state is process-local in this slice; daemon restart reconciliation is part of the asynchronous worker/journal increment
- no `registration.start` or `registration.cancel` ubus control is exposed yet
- no result event is emitted yet
- the existing initial registration path remains synchronous

## Cancellable transport safety layer — 2026-09-28

The registration executor now supports a caller-owned prestarted attempt and enforces attempt validity at these boundaries:

1. before local request preparation
2. before the main registration HTTP transfer
3. continuously during the libcurl transfer via `CURLOPT_XFERINFOFUNCTION`
4. after response classification and immediately before initial configuration/credential processing

A cancelled or stale attempt aborts the HTTP transfer and cannot enter credential persistence through the checked path. The original `send_request()` wrapper remains available for the legacy synchronous discovery flow; `cgw_run_registration_attempt(attempt_id)` is the controlled worker entry point.

Verification:

- active-attempt guard tests: PASS
- cancellation changes preserve all classifier and concurrency tests
- clean MT7621 package build: PASS
- deployed on enrolled AP with rollback binary retained
- AP remains `REGISTERED`, attempt `IDLE/NONE`, MQTT connected, online publish/PUBACK healthy

### Gate before exposing ubus cancellation

`cgw_process_initial_data()` currently asks netconfd to apply initial configuration before committing credentials. A cancellation arriving while netconfd is applying could otherwise produce partially applied configuration without credentials. Therefore `registration.cancel` remains unexposed until the attempt model adds an `APPLYING_CONFIG` non-cancellable phase or the configuration path provides rollback. The asynchronous API must return a stable `TOO_LATE_TO_CANCEL` result after that boundary. This is a release-blocking correctness requirement, not a deferred cosmetic improvement.

## Non-cancellable apply/commit boundary — 2026-09-28

Attempt states are now explicit:

```text
IDLE → PREPARING → HTTP → APPLYING_CONFIG → COMMITTING → COMPLETE
                 ↘ CANCELLED
```

Rules:

- `PREPARING` and `HTTP` are cancellable.
- `APPLYING_CONFIG` and `COMMITTING` are active but non-cancellable.
- Cancellation in either non-cancellable phase returns `TOO_LATE_TO_CANCEL`.
- Every phase change is compare-and-set against both attempt ID and expected phase.
- Skipped, repeated, stale and out-of-order transitions fail.
- A completion may finalize only the current active attempt.
- The configuration path enters `COMMITTING` only after netconfd accepts the initial configuration and before enrollment credentials are written.

Verification:

- unit tests cover cancellation during preparation, stale completion, exact phase transitions, `TOO_LATE_TO_CANCEL`, commit completion and concurrent start coalescing
- all decrypt and classification tests pass
- clean MT7621 package build passes
- deployed on enrolled AP with rollback binary preserved
- enrolled AP remains `IDLE/NONE`, MQTT connected, and wireless UCI unchanged

The phase model closes the partial-cancellation design gap. The next section records the completed worker shutdown/join and event-loop handoff implementation that permits the ubus methods to be exposed safely.

## Asynchronous ubus registration control

Implemented in `cgw_ubus.c` as a single joinable worker owned by cgwd. The ubus event loop never performs registration HTTP or initial configuration work.

- `ubus call cgwd registration.start` starts one attempt or joins the current attempt.
- `ubus call cgwd registration.cancel {"attempt_id":"..."}` cancels only during `PREPARING` or `HTTP`.
- Cancellation after configuration begins returns `TOO_LATE_TO_CANCEL`.
- Completion is emitted as the sanitized `air.cgwd.registration` event using schema `air.cgwd.registration.v1`.
- Worker completion crosses back to the libev thread through `ev_async`; ubus APIs are never called by the worker thread.
- The worker is joinable and is joined during normal cleanup, preventing detached work from outliving cgwd.
- An already enrolled AP returns `ALREADY_ENROLLED` and does not start a worker or contact the registration API.

### Target verification (2026-09-28)

- Clean MT7621 AirCNMS package build: PASS.
- Package SHA-256: `2a9a3b514b2d83c9e879dd45c5c41b3fa116c1cc00b91f84b8bd57d86fcd7f34`.
- Deployed `air-cgwd` SHA-256: `3474ec929e5e65ba2b29e1594bb15ef584cebb8c48aa2702a3a8537ce6d8a3f6`.
- cgwd service and MQTT reconnect: PASS.
- Enrolled `registration.start`: typed `ALREADY_ENROLLED`, no HTTP request.
- Unknown `registration.cancel`: typed `ATTEMPT_NOT_FOUND`.
- Status remained `REGISTERED`, MQTT connected, attempt state `IDLE`.
- Wireless UCI SHA-256 remained `f9dfc0b831132e045c1e27071501e75a05d3208012a051494eaf886d81c846d5`.

The live unregistered-device start/cancel path is deliberately not exercised on the enrolled test AP because doing so would require destructive identity reset. Its state transitions, cancellation boundaries, stale completion rejection, and concurrent coalescing are covered by host unit tests; a factory-state AP remains required for final hardware acceptance.

## Exact MQTT topic routing — 2026-09-28

The receive path no longer searches arbitrary payload or topic substrings to decide which privileged daemon receives a cloud message.

- The received topic must exactly equal one of the broker topics supplied during registration and stored in `cgw_topic_lst`.
- The exact final path component selects `config`, `cmd`, `bw_list`, or `rate_limit`.
- Unknown, unlisted, ambiguous broadcast, and lookalike topics fail closed.
- Command routing is determined by the command topic. `rf_scan` is recognized only from a strict JSON object whose single `cmd` field exactly equals `rf_scan`.
- Malformed JSON, trailing data, duplicate `cmd` keys, and strings that merely contain `cmd` or `rf_scan` do not trigger RF scanning.
- Initial registration configuration retains its explicit internal `initial_config` route and bounded 60-second ubus call.

Files:

- `src/managers/cgwd/inc/cgw_topic_route.h`
- `src/managers/cgwd/src/cgw_topic_route.c`
- `src/managers/cgwd/src/cgw_msgrx.c`
- `tests/test_cgw_topic_route.c`

Verification:

- decrypt tests: PASS
- registration classifier tests: PASS
- registration attempt tests: PASS
- topic router/adversarial payload tests: PASS
- clean MT7621 package build: PASS
- package SHA-256: `90d89bfbf79c3d81ec74b99124150d8b157af4cb456210a4172a0a820613d672`
- deployed cgwd SHA-256: `174463d9bfb4ced0f527eb78d0df130ab752ea35098819982d3a6f060065db5f`
- cgwd running, MQTT connected, enrollment `REGISTERED`: PASS
- enrolled registration start rejected as `ALREADY_ENROLLED`: PASS
- live retained configuration classified as exact `CONFIG`: PASS
- wireless UCI hash before/after: `f9dfc0b831132e045c1e27071501e75a05d3208012a051494eaf886d81c846d5`

The prior async cgwd binary is retained on the AP at `/root/air-onbd-backup/air-cgwd.phase2-async` for immediate rollback.

## MQTT lifecycle events and bounded reconnect — 2026-09-28

Cgwd now exposes a transport control independent of enrollment:

```sh
ubus call cgwd mqtt.reconnect
```

Contract:

- response schema: `air.cgwd.mqtt.reconnect.v1`
- accepted request: `ACCEPTED`
- another request inside 30 seconds: `THROTTLED` with `retry_after`
- invalid credentials/configuration or inactive worker: `NOT_READY`
- no credential, broker password, resource key, or complete connection configuration is returned

Lifecycle changes emit `air.cgwd.mqtt` with schema `air.cgwd.mqtt.v1`. The event contains only `connected`, `reason_code`, `broker_rc`, and a process-local monotonic `sequence`. Enrollment state is not changed by transport reconnects.

Real-AP verification:

- first request: `ACCEPTED`
- immediate second request: `THROTTLED`, `retry_after=30`
- ordered events: sequence 4 `GRACEFUL_DISCONNECT`, sequence 5 `CONNECTED`
- reconnect completed through the existing bounded retry timer; a failed first broker attempt was retried successfully
- final status: `REGISTERED`, MQTT connected, event sequence 5, queue depth 0
- cgwd remained running with no process restart
- wireless UCI SHA-256 remained `f9dfc0b831132e045c1e27071501e75a05d3208012a051494eaf886d81c846d5`
- deployed cgwd SHA-256: `14481bc51d994bfc5143adcb7edfc8dddb70e34c07e391c78d8e303c5ba97b54`
- package SHA-256: `629291f8122861f30f59e14b7b47ce2127cc89efcdb0ab4f5a57617c253a9b48`

The prior exact-routing binary is retained at `/root/air-onbd-backup/air-cgwd.phase2-routing`.

## Phase 2 disposition

The cgwd implementation now provides typed registration outcomes, stable attempt IDs, stale-result rejection, asynchronous start/cancel, non-cancellable apply/commit boundaries, credential-safe status, exact MQTT routing, transport lifecycle events, and bounded reconnect control.

Phase 2 implementation is complete. Final acceptance still requires a factory-state AP to exercise successful asynchronous registration and cancellation during an actual HTTP attempt without resetting the enrolled test AP. Existing enrolled-device compatibility has passed on hardware. Phase 3 netconfd job-contract work may begin without transferring production onboarding authority from cgwd to `air-onbd`.
