# aircnms trusted identity and authorization specification

Status: proposed implementation decision, 2026-09-07. Not implemented or target-qualified. Companion: [overview](ARCHITECTURE_OVERVIEW.md).

## 1. Decision and gate

Use **narrow authenticated ingress in the existing managers, bound to ubusd-authenticated service accounts**. No new broker daemon. Each owner accepts delegated identity only from explicitly permitted manager accounts and authorizes the requested resource itself.

This decision must be reviewed before Phase 1 public contract/ingress implementation. The target identity proof and baseline permission tests below must pass before any live write path is implemented. Schema sketches, source inspection, and isolated non-deployable mocks may proceed. Do not treat documentation of the mechanism as proof it works on the image.

A target unable to preserve the peer metadata or isolate ingress accounts is not qualified for this design. It requires an explicit revised decision, not a fallback to trusting payload roles or root-running managers.

## 2. Source evidence and limits

Inspected SDK root: `/home/airpro/projects/airpro/mtk/mt7621/sdk/cur/openwrt`.

| Inspected source under build_dir/target-mipsel_24kc_musl | Evidence |
| --- | --- |
| `ubus-2025.01.02~afa57cce/ubusd_acl.c` | `ubusd_acl_init_client` uses `SO_PEERCRED` and resolves user/group |
| `ubus-2025.01.02~afa57cce/ubusd_proto.c` | `ubusd_forward_invoke` constructs caller user/group attributes from the connected client |
| `ubus-2025.01.02~afa57cce/libubus-obj.c`, `libubus.h` | Request ACL metadata is exposed as `req->acl.user/group` separately from application data |
| `rpcd-2024.09.17~9f4b86e7/session.c` | Generic session data can be changed through `rpc_handle_set`; a mutable username alone is unsuitable as principal proof |
| Built `uhttpd*/ubus.c` | `uh_ubus_send_request` rejects caller-supplied nested `ubus_rpc_session` and inserts the outer session ID |

These observations establish implementation feasibility, not deployed ACL correctness. Record exact build hashes in test evidence. Upstream background: [ubus ACL source](https://lxr.openwrt.org/source/ubus/ubusd_acl.c). Newer upstream behavior must not be assumed identical to this SDK.

`SO_PEERCRED` on a service's connection to ubusd identifies the bus process, not the original RPC caller. Owners use the metadata reconstructed by ubusd, never `req->peer` as a stable principal and never application fields named `user`/`group`.

## 3. Accounts, trust, and registration

| Proposed OS account | Permitted delegation |
| --- | --- |
| `air-cgw` | Enrolled controller principal in its configured device/resource scope |
| `air-ui` | Protected authenticated local principal resolved through rpcd |
| `air-maint` | Maintenance coordination requests; cannot claim a human/cloud identity for arbitrary configuration |
| `air-policy` | Configured automation principal restricted to application enforcement intent |

Use distinct non-login UID/GID pairs; their numeric assignments are package-managed. Managers connect to ubus after entering their final account. Do not connect as root and then drop privilege: cached bus credentials would describe the wrong identity. Root-owned service executables, ACLs, account mappings, and policy files must not be writable by these accounts.

ubusd ACL files restrict object registration, invocation, subscriptions, and events by exact object/method. Owners also check `req->acl.user` against their allowed ingress accounts. Missing metadata, wrong account, or unexpected delegate type is rejected. Groups are not used as a broad substitute for the account check.

Object registration is restricted to its owner to prevent service-name impersonation. HTTP/rpcd ACLs expose only approved AirUI methods to browsers, not internal owner or lease APIs. Keep separate ACL manifests for ubusd and rpcd; their guarantees differ.

Root/compromised kernel, ubusd, rpcd, or a domain owner is outside this isolation guarantee. Root can alter code and credentials. Root recovery is a separately audited operational path, not evidence that the system can resist a hostile root.

## 4. WebUI identity flow

1. HTTP uses TLS for credential/token-bearing traffic and the supported rpcd login path. AirUI accepts a session bearer from this path; it never accepts a submitted role as authority.
2. Add a narrow rpcd integration method `air.auth.v1.resolve` callable only by `air-ui`. It validates session existence/expiry and obtains login identity from protected session state.
3. The integration stores an immutable principal UUID and authentication epoch at successful login in a dedicated session member, outside generic session data. Generic set/unset APIs cannot modify it. Sessions created without authenticated login have no privileged principal. Restored sessions must reauthenticate for this initial design.
4. `resolve` returns principal UUID, role IDs, authorization-policy generation, session expiry, and a non-secret session audit ID. Roles come from root-managed account policy, never request fields. It also checks the requested AirUI method via rpcd access rules.
5. AirUI forwards a delegated context under its `air-ui` bus identity. The domain owner intersects that context with current resource policy and executes its normal authorization checks.

This is an SDK rpcd integration change, not a new daemon. It is required work; `session.get(username)` is not an acceptable substitute. Do not expose `resolve` or session enumeration to browser roles. A mock resolver may support tests but cannot enable writes on a target.

Resolve every mutation, confirmation, sensitive result read, and cancellation without a positive authorization cache. Fail closed on resolver failure. Session logout cannot undo accepted work; subsequent privileged calls require valid authentication. Authorization already admitted to a running operation is recorded, not repeatedly changed halfway through platform effects.

## 5. Cloud and internal flows

`cgwd` verifies controller authentication, enrollment binding, command expiry/replay rules, and allowed scope before constructing a context. Principal UUID is stable for the controller enrollment, not an MQTT connection or certificate serial. Rotation of a credential preserves that identity; re-enrollment creates a new epoch so old retries cannot cross controller ownership.

Owners accept cloud delegation only from `air-cgw`, with locally provisioned scope as an upper bound. A controller cannot broaden that bound by submitting a role or resource list. Cloud compromise has the authority of its enrolled scope, not every local role.

`acld` submits under a stable automation identity through `air-policy` with only approved rule resources. `cmdexecd` uses `air-maint` and its operation reference for lease calls; it cannot use that identity to impersonate an administrator.

## 6. Delegation envelope and owner validation

Application payload contains `auth_context` with: `schema=1`, `principal_id`, `principal_epoch`, `origin`, `role_ids`, `scope_id`, `policy_generation`, `session_audit_id` where relevant, and `request_id`. All identifiers have schema limits. Bearer session IDs and passwords are excluded. The envelope is trusted only because of the allowed ingress bus identity; it is not independently signed and must never be accepted from arbitrary clients.

Owner validation order: bound/parse request → verify bus account → validate permitted origin/delegation kind → check policy generation and principal scope → authorize method and every resource → resolve idempotency → acquire mutation slot and recheck revision/preconditions → journal admission. Rejected unauthorized requests must not disclose another principal's deduplication record.

The owner uses its current protected policy; stale generations are rejected for re-resolution. Policy deployment must update owner enforcement before ingress advertises a new grant. Revoking future access does not remove the owner's authority to finish recovery for already accepted operations.

Idempotency scope is `(principal_id, principal_epoch, owner_object, method, key)`. It excludes temporary session and connection IDs. Canonical payload hashing excludes request ID, transport deadline, and authentication bearer, but includes resource intent and confirmation policy. Audit captures principal/epoch, ingress account, method/resources, decision, policy generation, operation ID, and outcome; no secrets or raw sensitive payloads.

## 7. Baseline permission matrix

Default deny; resource restrictions and method-specific preconditions further narrow every grant. This baseline is a write implementation gate. Expand and test the complete method/field catalog before production sign-off.

| Method class | Guest/unauthenticated | Viewer | Local admin | Scoped cloud controller | Recovery admin | Automation | Maintenance service |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Minimal public readiness | Sanitized only | Yes | Yes | Yes | Yes | Own dependencies | Own dependencies |
| Config/capability reads | No | Redacted permitted fields | Yes | Scoped | Yes | Own rules | Needed preconditions |
| Station/history/log reads | No | Explicit read grant only | Redacted | Scoped read grant | Explicit read grant | Required observations | Own job data |
| Validate/apply | No | No | Unlocked resources | Scoped resources | Recovery actions only | Expiring rule intent only | No |
| Operation lookup/cancel | No | No | Own; others with explicit grant | Own scoped | Recovery grant | Own | Own |
| Confirm | No | No | Own token + valid role | Own token + scope | No automatic takeover | No | No |
| Reboot/reset/upgrade | No | No | Explicit disruptive grant | Explicit scoped disruptive grant | Explicit recovery action | No | Execute accepted job |
| Lease acquire/release | No | No | No | No | No | No | Yes, matching job |
| Adopt/restore recovery state | No | No | No by default | No by default | Explicit activated local recovery | No | No |

Recovery admin is a separately activated, time-bounded local recovery role, not a role a caller sets in JSON. Its activation and credential provisioning must be included in the first target profile. No universal default password is introduced.

## 8. Confirmation-token protocol

Owner creates 32 random bytes using the OS CSPRNG at entry to `awaiting_confirmation`. Return base64url token only in `operation_get` as `confirmation.token`, over authenticated TLS-backed adapter delivery, to the original principal with the same active UI session or cloud enrollment epoch. Polling may retrieve the same token until consumption/expiry in the same owner process; unrelated callers never receive it.

TTL is 120 seconds by default, measured from entry using monotonic time; allowed profile bounds are 30–300 seconds. Owner caps the requested timeout and returns remaining seconds. Token is bound to operation ID, candidate digest, principal/epoch and initiating session identity where applicable. Comparison uses a constant-time implementation. The secret exists only in owner memory; the journal stores its SHA-256 verifier and binding, not the secret. Never include it in events, audit, URLs, or normal cached status.

`confirm` carries `operation_id` and `confirmation.token`. Consume once by durably committing the succeeded state and token-consumed marker in the same journal generation. A retry after durable success returns the terminal result to the authorized initiator and causes no new confirmation action. Tokens cannot confirm a different revision or operation.

If a reply is lost but the initiating session and owner are alive, the caller can retrieve the same token again. If the token is irretrievable because the owner restarted, the initiating UI session was lost, or the deadline expired, **automatic rollback is intended**. No token reissue, session takeover, or deadline extension in v1. Recovery administrators may restore through recovery procedures, but cannot silently confirm an unknown candidate. On transport timeout around final commit, look up the durable outcome before assuming rollback.

## 9. Secrets at rest

Baseline profile provides filesystem isolation, not encryption against root or physical flash extraction. Persistent credentials and secret-bearing journals use owner-only files/directories and are omitted from routine support bundles. UCI/portal runtime secret copies have the same explicit limitation. Confirmation secrets are memory-only; persisted verifiers are not bearer credentials.

Do not claim encryption by storing an encryption key next to ciphertext. A hardware-backed profile may encrypt protected artifacts only with an identified device-bound key facility, authenticated encryption, rotation and recovery procedure; it must cover temporary files, snapshots, generated configs and backups too. Hardware support is not assumed. If product requirements demand extraction-resistant secrets, boards without that profile fail the production gate.

## 10. Target proof checklist

Before writes: demonstrate distinct accounts; spoofed payload user/role rejection; missing/forged bus metadata rejection; object-registration isolation; browser denial of internal RPC; immutable login principal despite generic session mutation attempts; session expiry/logout; root/session restore behavior; scope restrictions; and sensitive operation lookup isolation. Capture source/image hashes and ACL manifests.

Before production: generate negative cases from the full role/method/resource catalog, test policy-generation changes, enrollment rotation, lost confirmation replies, repeated tokens, restart rollback, credential retention/redaction and secure recovery activation. Pending these checks, the identity gate is **open (not passed)**.
