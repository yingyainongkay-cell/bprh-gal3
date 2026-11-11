# FROZEN_SPEC_GAL3 — GAL-3 (BPRH/SEOS) Technical Specification

| | |
|---|---|
| Milestone | M2 — Spec Freeze, amended by M2.1 |
| Revision | 2 (M2.1 closes OG-01 to OG-06 and OG-09; see §9 and §10) |
| Status | FROZEN. Items in §9 "Open gaps" are explicitly **not** frozen. |
| Date | 2026-11-11 |
| Role | ARCHITECT |
| Companion files | `THREAT_MODEL.md`, `openapi.yaml` |

---

## 0. How to read this spec

### 0.1 Source material

Two kinds of source feed this spec.

**Research files**, all accessed 2026-11-11. They were delivered together in a single attachment; the file names below are the ones cited throughout.

| Short name | File | Covers |
|---|---|---|
| OPA | `opa-patterns.md` | Rego v1, allow/deny, tenant isolation, `opa test` |
| ED25519 | `ed25519-rfc8032.md` | RFC 8032, PyNaCl API, test vectors, pitfalls, JWT/EdDSA |
| CLICKHOUSE | `clickhouse-audit-schema.md` | MergeTree vs ReplacingMergeTree, hash-chain table, TTL, chain-break query, partitions |
| REDIS | `redis-rate-limit.md` | Token bucket, Lua atomicity, fail-closed/open, FastAPI, throughput |

**M2.1 decisions**, supplied by the project owner on 2026-11-11 to close specific gaps. They are cited by the gap they close.

Citation formats: `[file › section]` for research, `[M2.1 › OG-nn]` for decisions.

### 0.2 Statement classes

| Class | Meaning |
|---|---|
| **Adopted** | Taken directly from a research file. Cited. |
| **Decided** | An explicit M2.1 decision. Cited. |
| **Derived** | Needed to make the spec complete and follows mechanically from research or decisions, with no alternative chosen. Marked *(Derived)*. Every rev-2 derivation is listed in §10.2 so it can be vetoed. |
| **Gap** | Not covered. Never filled by assumption. Listed in §9 as `OG-nn` and referenced where it bites. |

### 0.3 Freeze rules

1. No new design decisions beyond research and M2.1. Where both are silent, the spec says so and points to §9.
2. No code. Policies, schemas and algorithms are specified as tables and prose. Snippets in the research files are referenced by section, not reproduced, and OG-10 records where they must not be treated as normative.
3. Self-contained, with one stated exception: public signing keys live in the file `specs/TRUST_ANCHORS.md` [M2.1 › OG-04], which is operationally external to this document (OG-15).

---

## 1. System overview

### 1.1 Purpose

The sources do not state a business purpose for GAL-3 (OG-12). What they define is a service composed of four capabilities:

1. **Tenant-isolated authorization**, decided by OPA policy with default deny, on identity taken from an EdDSA-signed JWT. [opa-patterns.md › Allow/Deny Pattern, Tenant Isolation Pattern; M2.1 › OG-06]
2. **Tamper-evident audit logging**, stored as an append-only ClickHouse table with one hash chain per tenant. [clickhouse-audit-schema.md › Hash-Chain Audit Table; M2.1 › OG-01]
3. **Ed25519 signing and verification** per RFC 8032, with the private key held off-service. [ed25519-rfc8032.md › PyNaCl API; M2.1 › OG-04]
4. **Rate limiting**, using a Redis token bucket updated atomically by a Lua script. [redis-rate-limit.md › Lua Script for Atomic Token Bucket]

### 1.2 Scope

| In scope | Out of scope (not covered) |
|---|---|
| JWT identity mapping and authorization policy contract | Token issuance, validation details, JWT key distribution (OG-17) |
| Per-tenant audit table, hash-chain rules, retention | Business domain resources beyond the four capabilities (OG-12) |
| Key custody model, versioning, public-key registry, signed-content format | The interface to the signing authority and registry operations (OG-14, OG-15) |
| Token-bucket algorithm and failure-mode classification | Replay-protection policy (OG-16) |
| Sign and verify flow | Deployment topology, HA, TLS, observability (OG-13) |
| REST contract exposing the four capabilities | Pagination, API versioning policy, error-body standard (OG-12) |

### 1.3 Actors

| Actor | Description | Basis |
|---|---|---|
| Tenant admin | Authenticated user with `role` = `admin`, belonging to one tenant (`user.tenant_id`). The only role the policy authorizes. | [opa-patterns.md › Allow/Deny Pattern] |
| Other tenant user | Authenticated user with any other role value. Denied by default. | [opa-patterns.md › Allow/Deny Pattern] (default deny) |
| Cross-tenant caller | Authenticated user whose `tenant_id` differs from the resource's. Always denied, with a reason message. | [opa-patterns.md › Tenant Isolation Pattern] |
| HRA | External signing authority. Holds the Ed25519 private key; it is not part of the API service. The acronym is used as supplied and is not expanded in the source material. | [M2.1 › OG-04] |
| Operator / CI | Runs policy checks and tests in the pipeline. Not a runtime role. | [opa-patterns.md › OPA and Rego v1] |

### 1.4 Components

| Component | Role | Basis |
|---|---|---|
| API service | Hosts the REST endpoints; Python, with FastAPI middleware or dependencies | [redis-rate-limit.md › FastAPI Implementation]; PyNaCl is a Python library [ed25519-rfc8032.md] |
| OPA | Policy decision point; package `authz`, Rego v1 | [opa-patterns.md] |
| ClickHouse | Audit store; table `audit_log` | [clickhouse-audit-schema.md] |
| Per-tenant append serializer | Lock or queue that serializes audit appends for each tenant; mechanism not chosen (OG-18) | [M2.1 › OG-02] |
| Redis | Rate-limit state store; Lua script executed with `EVAL` | [redis-rate-limit.md] |
| HRA | Produces Ed25519 signatures with the off-service private key (interface: OG-14) | [M2.1 › OG-04] |
| Trust anchors registry | File `specs/TRUST_ANCHORS.md` holding public keys by `key_id` (operation: OG-15) | [M2.1 › OG-04] |
| PyNaCl | Ed25519 verification in the API service | [ed25519-rfc8032.md › PyNaCl API] |

### 1.5 Request processing order *(Derived)*

1. The caller sends a request with a JWT. The token is verified (§4.1) and its claims become `input.user` for OPA.
2. The rate-limit check runs before the handler. [redis-rate-limit.md › FastAPI Implementation]
3. The authorization decision is requested from OPA; anything other than `allow = true` is a denial (default deny).
4. The handler runs (audit append, audit query, chain verification, sign, or verify).
5. The response is returned.

Steps 2 and 3 must both succeed before step 4. Their relative order is not specified (OG-13).

---

## 2. API endpoints (REST)

The research defines capabilities, not endpoints. The inventory below is the **minimal set that exposes each capability once** *(Derived)*. Path names, the `/v1` prefix and parameter names are provisional wording (OG-12); the capabilities and fields they carry are not.

### 2.1 Endpoint inventory

| ID | Method | Path | Capability | Success | Rate-limit failure mode | Basis |
|---|---|---|---|---|---|---|
| A1 | POST | `/v1/audit/events` | Append an audit event to the caller's tenant chain | 201 | **Fail-closed** (critical) | [clickhouse-audit-schema.md › Hash-Chain Audit Table]; [M2.1 › OG-09] |
| A2 | GET | `/v1/audit/events` | Read the caller's tenant audit events in a time range | 200 | **Fail-open** (non-critical) | [clickhouse-audit-schema.md › Partition Strategy]; [M2.1 › OG-09] |
| A3 | GET | `/v1/audit/chain/verification` | Check the caller's tenant chain in a time range | 200 | **Fail-open** (non-critical) | [clickhouse-audit-schema.md › Query Pattern: Detect Chain Break]; [M2.1 › OG-09] |
| S1 | POST | `/v1/signatures/sign` | Sign a message with Ed25519 | 200 | **Fail-closed** (critical) | [ed25519-rfc8032.md › PyNaCl API]; [M2.1 › OG-04, OG-09] |
| S2 | POST | `/v1/signatures/verify` | Verify an Ed25519 signature against a registered key | 200 | **Fail-closed** (critical) | [ed25519-rfc8032.md › PyNaCl API]; [M2.1 › OG-04, OG-09] |

Cross-cutting rules for every endpoint:

- **Authentication:** a valid JWT is required (§4.1).
- **Authorization:** the OPA decision must be `allow = true` (§4.7).
- **Rate limiting:** a token is consumed per request (§5). The failure mode is the one in the table above.
- **Tenant scoping** *(Derived)*: all audit operations act on the caller's own tenant, taken from `user.tenant_id`. No audit operation has a tenant parameter, and request bodies never carry `tenant_id`.

### 2.2 Request and response schemas

**A1 — POST `/v1/audit/events`**

| Direction | Field | Type | Notes |
|---|---|---|---|
| Request | `action` | string | Maps to `audit_log.action` |
| Request | `payload` | string | Maps to `audit_log.payload`; opaque string, content format not specified (OG-12) |
| Response 201 | `tenant_id` | string | The caller's tenant |
| Response 201 | `sequence` | integer ≥ 0 | Assigned by the server; monotonic per tenant (§3.3) |
| Response 201 | `ts` | date-time | Server-assigned. JSON form used for hashing: OG-19 |
| Response 201 | `actor` | string | The JWT `sub` claim *(Derived)* |
| Response 201 | `action`, `payload` | string | Echo of stored values |
| Response 201 | `prev_hash`, `hash` | string, 64 lowercase hex chars | Chain linkage (§3.3) |

**A2 — GET `/v1/audit/events`**

| Direction | Field | Type | Notes |
|---|---|---|---|
| Query | `from` | date-time, required | Range start, inclusive (provisional, OG-12) |
| Query | `to` | date-time, required | Range end, exclusive (provisional, OG-12) |
| Response 200 | `events` | array of audit event | Same fields as the A1 response; caller's tenant only; ordered by `sequence` *(Derived)* |

**A3 — GET `/v1/audit/chain/verification`**

| Direction | Field | Type | Notes |
|---|---|---|---|
| Query | `from`, `to` | date-time, required | As A2. The predecessor of the first row in range is the row with the next lower `sequence` in the same tenant chain, wherever it falls in time. |
| Response 200 | `intact` | boolean | `true` when `breaks` is empty *(Derived)* |
| Response 200 | `breaks` | array | One item per row failing a chain check (§3.3, rule C6) |
| Response 200 | `breaks[].sequence`, `.ts`, `.actor`, `.prev_hash`, `.hash` | as stored | The research query's four columns plus `sequence`, which now locates the row *(Derived)* |
| Response 200 | `breaks[].reason` | `prev_hash_mismatch` or `hash_mismatch` | Which check failed *(Derived; values provisional, OG-12)* |

**S1 — POST `/v1/signatures/sign`**

| Direction | Field | Type | Notes |
|---|---|---|---|
| Request | `message` | string | Carried as a JSON string inside the signed content (§6.4) |
| Response 200 | `signature` | string, 128 lowercase hex chars | 64-byte Ed25519 signature, hex-encoded [M2.1 › OG-05] |
| Response 200 | `key_id` | string | Version of the key that signed (§6.2) |
| Response 200 | `nonce` | string | UUID v4 generated at signing time *(Derived: the verifier needs it to rebuild the signed content)* |
| Response 200 | `timestamp` | string | ISO 8601 time generated at signing time *(Derived, same reason)*; carried verbatim |

**S2 — POST `/v1/signatures/verify`**

| Direction | Field | Type | Notes |
|---|---|---|---|
| Request | `message` | string | As signed |
| Request | `nonce` | string | As returned by S1 |
| Request | `timestamp` | string | As returned by S1, verbatim |
| Request | `signature` | string, 128 lowercase hex chars | As returned by S1 |
| Request | `key_id` | string | Looked up in the trust anchors registry; callers can no longer supply a public key [M2.1 › OG-04] |
| Response 200 | `valid` | boolean | `false` for a bad signature, and also for an unknown `key_id` *(Derived, provisional: OG-15)* |

Meaning of `valid = true`: the signature is consistent with this message, nonce and timestamp, under a key listed in the registry. It does not say whether the nonce was seen before or whether the timestamp is acceptable (OG-16).

### 2.3 Error responses

Status codes use standard HTTP semantics. They are **not** from research or M2.1 (OG-12).

| Status | Condition |
|---|---|
| 400 | Malformed request, including values that violate the hex or length rules |
| 401 | Missing or invalid JWT (§4.1) |
| 403 | OPA decision is not `allow`. May carry the deny message, for example "cross-tenant access denied". [opa-patterns.md › Allow/Deny Pattern] |
| 429 | Rate limiter returned `allowed = 0`. [redis-rate-limit.md › Lua Script for Atomic Token Bucket] |
| 503 | Rate-limit store unavailable on a fail-closed endpoint (A1, S1, S2 only). [redis-rate-limit.md › Fail-Closed vs Fail-Open; M2.1 › OG-09] |

---

## 3. Data models

### 3.1 ClickHouse table `audit_log`

| Column | Type | Meaning | Basis |
|---|---|---|---|
| `tenant_id` | String | Tenant that owns the row and its chain | [M2.1 › OG-01] |
| `sequence` | UInt64 | Position in the tenant's chain; monotonic per tenant | [M2.1 › OG-02] |
| `ts` | DateTime | Event time | [clickhouse-audit-schema.md] |
| `actor` | String | Who performed the action (the JWT `sub`) | [clickhouse-audit-schema.md]; [M2.1 › OG-06] |
| `action` | String | What was done | [clickhouse-audit-schema.md] |
| `payload` | String | Event detail | [clickhouse-audit-schema.md] |
| `prev_hash` | FixedString(64) | `hash` of the preceding row in the same tenant chain | [clickhouse-audit-schema.md] |
| `hash` | FixedString(64) | This row's hash | [clickhouse-audit-schema.md] |

Table parameters [clickhouse-audit-schema.md › Hash-Chain Audit Table, Partition Strategy, TTL Policy]:

| Parameter | Value |
|---|---|
| Engine | MergeTree |
| ORDER BY | `(ts, actor)` — unchanged from research; whether to add `tenant_id` and `sequence` is open (OG-18) |
| PARTITION BY | `toYYYYMM(ts)` (monthly) |
| TTL | `ts + INTERVAL 7 YEAR` |
| Setting | `ttl_only_drop_parts = 1` (recommended by research), so expired data is dropped by whole part |

### 3.2 Engine choice

| Engine | Behavior per research | Use here |
|---|---|---|
| MergeTree | Append-only; every insert is a new row; no dedup | **Selected** for audit: immutability required |
| ReplacingMergeTree | Upsert via version column; dedup during merge; suited to "latest state" | Not used |

[clickhouse-audit-schema.md › MergeTree vs ReplacingMergeTree]

### 3.3 Hash-chain rules

| Rule | Statement | Basis |
|---|---|---|
| C1 | **One chain per tenant.** Rows with different `tenant_id` are never linked. | [M2.1 › OG-01] |
| C2 | **Ordering.** `sequence` is a `UInt64`, monotonic per tenant, and defines a row's position in its chain. Appends for a tenant are serialized by a per-tenant lock or queue so no two rows of one tenant are computed from the same predecessor. | [M2.1 › OG-02] |
| C3 | **Hash.** `hash` = SHA-256, written as 64 lowercase hex characters *(hex form Derived from FixedString(64) and a 32-byte digest)*, computed over the JCS (RFC 8785) serialization of an object with exactly these fields: `ts`, `actor`, `action`, `payload`, `prev_hash`. The `hash` column itself is excluded. | [M2.1 › OG-03] |
| C4 | **First row.** The first row of a tenant chain has `prev_hash` = SHA-256 of the string `GENESIS`, which is `901131d838b17aac0f7885b81e03cbdc9f5157a00343d30ab22083685ed1416a`. | [M2.1 › OG-03] |
| C5 | **Append-only.** Rows are only inserted, never replaced (engine choice, §3.2). | [clickhouse-audit-schema.md › MergeTree vs ReplacingMergeTree] |
| C6 | **Verification** *(Derived)*. Per tenant, taking rows in `sequence` order, a row is a break if (a) its `prev_hash` differs from its predecessor's `hash` (or from the genesis value for the first row), or (b) its `hash` differs from the value recomputed under C3. Check (a) is the research's chain-break pattern, reordered by `sequence`; check (b) is added because C3 now makes recomputation possible, and without it a changed row whose stored `hash` was left alone would pass. | [clickhouse-audit-schema.md › Query Pattern: Detect Chain Break]; [M2.1 › OG-03] |
| C7 | **Expiry.** Rows expire only through TTL, at part granularity, after 7 years. | [clickhouse-audit-schema.md › TTL Policy] |

Not settled by the decisions: the JSON form of `ts` used in hashing, the fact that `tenant_id` and `sequence` are not hash inputs, and re-anchoring once TTL removes a chain's oldest rows (OG-19); the lock or queue mechanism, first `sequence` value and recovery after a crash (OG-18); and how the database prevents modification (OG-11).

### 3.4 Redis rate-limit state

| Item | Specification |
|---|---|
| Key | One key per limited subject, passed to the script as its single key. The subject scheme is not specified (OG-08). |
| Structure | Hash with two fields: `tokens` and `last_refill` |

[redis-rate-limit.md › Lua Script for Atomic Token Bucket, Performance at 1000 req/s]

### 3.5 Policy documents (OPA)

| Document | Content |
|---|---|
| Input | `user.tenant_id`, `user.role`, `user.sub` (all from JWT claims), and `resource.tenant_id` |
| Output | `allow` (boolean, default `false`); `deny` (set of message strings) |

The current rules do not use `user.sub`; it is available for later rules (OG-07). [opa-patterns.md › Allow/Deny Pattern; M2.1 › OG-06]

### 3.6 Signing data

| Item | Specification |
|---|---|
| Signed content | JCS serialization of `{context, nonce, timestamp, message}` (§6.4) |
| Signature | 64 bytes, lowercase hex (128 characters) |
| Key registry record | `key_id`, `created_at`, `public_key` (lowercase hex) |

Nothing else is persisted by this design. [M2.1 › OG-04, OG-05]

---

## 4. Authentication and authorization

### 4.1 Authentication (JWT)

| Item | Specification |
|---|---|
| Token | JWT signed with EdDSA using Ed25519 (RFC 8037) |
| Claims | `tenant_id`, `role`, `sub` |
| Mapping | Claims map directly to OPA input: `user.tenant_id`, `user.role`, `user.sub` |
| Algorithm handling | Only EdDSA is accepted; tokens using any other algorithm are rejected *(Derived from the EdDSA decision)* |
| Failure | Missing or invalid token yields 401 |

[M2.1 › OG-06]; [ed25519-rfc8032.md › JWT with EdDSA vs Ed25519]. Issuer, audience, expiry rules and key distribution are not decided (OG-17).

### 4.2 Engine and syntax

- OPA 1.0; Rego v1 is the default syntax. `if`, `contains` and `in` are built in; `import future.keywords` is not needed. [opa-patterns.md › OPA and Rego v1]
- Package name: `authz`. [opa-patterns.md › Allow/Deny Pattern]

### 4.3 Rules

| ID | Rule | Condition | Result |
|---|---|---|---|
| Z1 | Default | No rule matched | `allow = false` |
| Z2 | Allow | `user.tenant_id` equals `resource.tenant_id` **and** `user.role` equals `"admin"` | `allow = true` |
| Z3 | Deny reason | `user.tenant_id` differs from `resource.tenant_id` | `deny` contains "cross-tenant access denied" |
| Z4 | Tenant check first | Every rule that grants access | Must check tenant equality before granting, to prevent cross-tenant leaks |

[opa-patterns.md › Allow/Deny Pattern, Tenant Isolation Pattern]. The reference Rego for Z1–Z3 is in that file and is adopted unchanged.

### 4.4 Decision matrix

| Caller | Same tenant? | Role | `allow` | `deny` |
|---|---|---|---|---|
| Admin | Yes | `admin` | true | empty |
| Non-admin | Yes | other | false (default) | empty |
| Admin | No | `admin` | false | contains cross-tenant message |
| Non-admin | No | other | false | contains cross-tenant message |
| Any | Required attribute missing | any | false (default deny) | empty |

The last row follows from default deny and Rego's treatment of undefined values *(Derived)*.

### 4.5 Consequences of the adopted rules

1. No role other than `admin` is ever allowed.
2. The input has no action or method, so the policy cannot distinguish one endpoint from another. Under the frozen policy, every endpoint in §2.1 is reachable only by a same-tenant admin. Finer rules are OG-07.
3. `deny` is informational: `allow` does not consult it. How the enforcement point consumes `deny` is not specified (OG-07).

### 4.6 Quality gates

| Gate | Command | Purpose |
|---|---|---|
| Strict check | `opa check --strict` | Run in CI |
| Format | `opa fmt --rego-v1` | Run in CI |
| Tests | `opa test ./policies/` | Test file kept separate from the policy; must cover allow, deny and edge cases (tenant mismatch, differing roles) |

[opa-patterns.md › OPA and Rego v1, Testing with opa test]

### 4.7 Endpoint binding *(Derived)*

Every endpoint in §2.1 requires `allow = true`. For audit operations, `resource.tenant_id` is the tenant of the chain being accessed, which is the caller's own tenant (§2.1, tenant scoping). It comes from the server-side tenant scope or the stored row, never from request input. For S1 and S2 there is no stored resource; which tenant they are evaluated against is not defined (OG-07).

---

## 5. Rate limiting strategy (Redis)

### 5.1 Algorithm

Token bucket. The comparison heading in the research lists sliding window as well, but only the token-bucket pattern is detailed, and the task scopes this spec to it. [redis-rate-limit.md › Token Bucket vs Sliding Window]

### 5.2 Parameters

| Parameter | Meaning | Source position |
|---|---|---|
| `capacity` | Maximum tokens in the bucket | 1st argument |
| `refill_rate` | Tokens added per elapsed refill interval | 2nd argument |
| `refill_interval` | Length of one refill interval | 3rd argument |
| `now` | Current time, supplied by the caller | 4th argument |

`refill_interval` and `now` must use the same time unit; the unit is not specified. Values for each endpoint class are unassigned (OG-08).

### 5.3 Algorithm steps

Per request, executed as one atomic unit:

1. Read `tokens` and `last_refill` from the key's hash. If absent, start with a full bucket (`tokens = capacity`) and `last_refill = now` *(Derived from the evident intent of the research snippet; see OG-10)*.
2. Compute whole elapsed refills: floor of (`now` − `last_refill`) ÷ `refill_interval`.
3. If at least one refill elapsed: `tokens` = min(`capacity`, `tokens` + refills × `refill_rate`), and `last_refill` advances by refills × `refill_interval` (not to `now`, so partial intervals are kept).
4. If `tokens` ≥ 1: subtract 1 and mark the request allowed; otherwise mark it denied.
5. Write `tokens` and `last_refill` back.
6. Return the pair (allowed flag, remaining tokens).

[redis-rate-limit.md › Lua Script for Atomic Token Bucket]. The algorithm above is normative; the research snippet is not (OG-10).

### 5.4 Atomicity

The read-decide-update sequence runs as a Lua script via `EVAL` so it is atomic and free of race conditions. [redis-rate-limit.md › Lua Script for Atomic Token Bucket]

### 5.5 Failure mode

| Mode | Behavior when Redis is down | Trade-off |
|---|---|---|
| Fail-closed | Deny every request | Safe; low availability |
| Fail-open | Allow every request | High availability; abuse risk |

Research recommendation: fail-closed for critical endpoints, fail-open for non-critical ones. [redis-rate-limit.md › Fail-Closed vs Fail-Open]

Classification, **decided** [M2.1 › OG-09]:

| Class | Endpoints | Mode |
|---|---|---|
| Critical | A1, S1, S2 | Fail-closed (503 when Redis is unavailable) |
| Non-critical | A2, A3 | Fail-open |

### 5.6 Integration and performance

- Integration: FastAPI middleware or dependency that calls the script through `redis.eval()` before the handler. [redis-rate-limit.md › FastAPI Implementation]
- Performance: the design target noted in research is 1000 req/s; token bucket needs low memory (one hash per key). [redis-rate-limit.md › Performance at 1000 req/s]

---

## 6. Signing and verification flow (Ed25519)

### 6.1 Standard and library

- RFC 8032 (EdDSA), January 2017, Proposed Standard; the primary reference for Ed25519. [ed25519-rfc8032.md › RFC 8032 Status]
- Library for verification in the API service: PyNaCl, `nacl.signing`, with `VerifyKey` (public); keys are based on a 32-byte seed. [ed25519-rfc8032.md › PyNaCl API]
- Variant: plain Ed25519. The research gives API guidance for no other variant, so the other variants listed in RFC 8032 are out of scope.

### 6.2 Key custody and rotation

| Item | Specification |
|---|---|
| Private key | Held by HRA, off-service. The API service never holds it. |
| Versioning | Each key version has a `key_id` and `created_at` |
| Rotation | Every 90 days |
| Active key | New signatures use the newest key version *(Derived from versioned keys)* |

[M2.1 › OG-04]. The format of `key_id`, the rotation procedure and handling of retired keys are open (OG-15).

### 6.3 Key registry

Public keys are published in `specs/TRUST_ANCHORS.md`, one record per key version: `key_id`, `created_at`, `public_key` as lowercase hex. S2 resolves `key_id` against this registry; a caller-supplied public key is no longer accepted. [M2.1 › OG-04]. The file does not exist yet, and how the service loads and trusts it is open (OG-15).

### 6.4 Signed content

The bytes that are signed are the JCS (RFC 8785) serialization of one JSON object with these members:

| Member | Value |
|---|---|
| `context` | The constant string `gal3-sign` |
| `nonce` | A UUID v4 |
| `timestamp` | An ISO 8601 time string |
| `message` | The caller's message, as a JSON string |

[M2.1 › OG-05]. `context` is fixed and never sent by callers. `nonce` and `timestamp` are carried verbatim from S1 to S2, so the verifier rebuilds exactly the bytes that were signed.

### 6.5 Sign flow (S1)

1. Authentication, authorization and rate-limit checks pass (§1.5).
2. The service builds the signed content: fixed `context`, fresh `nonce`, current `timestamp`, and the caller's `message` *(Derived: who builds it; see OG-14)*.
3. The content is serialized with JCS.
4. HRA signs those bytes with the current private key; the signature is always 64 bytes. [ed25519-rfc8032.md › Common Pitfalls]. The service-to-HRA interface is open (OG-14).
5. The service returns the signature as lowercase hex, the `key_id`, the `nonce` and the `timestamp`.

### 6.6 Verify flow (S2)

1. Authentication, authorization and rate-limit checks pass.
2. Reject requests whose `signature` is not exactly 128 lowercase hex characters (400).
3. Resolve `key_id` in the registry. If it is not listed, return `valid = false` *(Derived, provisional: OG-15)*.
4. Decode the signature and the registered public key from hex.
5. Rebuild the signed content from `message`, `nonce`, `timestamp` and the fixed `context`; serialize with JCS.
6. Verify with the `VerifyKey`, passing both message and signature correctly. If the library raises BadSignatureError, return `valid = false`; otherwise `valid = true`. [ed25519-rfc8032.md › PyNaCl API, Common Pitfalls]
7. Checking the nonce for reuse and the timestamp for freshness is not defined (OG-16).

### 6.7 Encoding and pitfalls

| Pitfall | Requirement |
|---|---|
| Encoding: hex vs raw bytes | Lowercase hex for `signature` and `public_key`, on both sides [M2.1 › OG-05] |
| Padding | None. Unlike RSA, signature length is fixed at 64 bytes (128 hex characters) |
| Verify arguments | Pass message and signature correctly to the verify call |

[ed25519-rfc8032.md › Common Pitfalls]

### 6.8 Conformance

Any implementation of Ed25519 operations, including HRA's if it can be tested, must pass the Ed25519 test vectors in RFC 8032 §7.1. [ed25519-rfc8032.md › Test Vectors]

---

## 7. Traceability matrix

| Spec section | Source |
|---|---|
| §2 A1–A3 | clickhouse-audit-schema.md (Hash-Chain Audit Table; Query Pattern; Partition Strategy); M2.1 OG-01, OG-02, OG-03, OG-09 |
| §2 S1–S2 | ed25519-rfc8032.md (PyNaCl API); M2.1 OG-04, OG-05, OG-09 |
| §3.1–3.3 | clickhouse-audit-schema.md (all sections); M2.1 OG-01, OG-02, OG-03 |
| §3.4, §5 | redis-rate-limit.md (all sections); M2.1 OG-09 |
| §3.5, §4 | opa-patterns.md (all sections); M2.1 OG-06 |
| §3.6, §6 | ed25519-rfc8032.md (all sections); M2.1 OG-04, OG-05 |

---

## 8. Acceptance checks

From research:

1. `opa check --strict`, `opa fmt --rego-v1` and `opa test ./policies/` pass in CI. [opa-patterns.md]
2. RFC 8032 §7.1 test vectors pass. [ed25519-rfc8032.md]
3. The chain verification runs against the audit table and reports no breaks on untampered data. [clickhouse-audit-schema.md]
4. The rate-limit script is atomic and its failure mode matches the class assigned in §5.5. [redis-rate-limit.md]

From M2.1 *(Derived)*:

5. The first row of every tenant chain has `prev_hash` equal to the genesis value in rule C4.
6. Appending for one tenant never changes another tenant's chain.
7. A token signed with any algorithm other than EdDSA is rejected with 401.
8. S2 cannot be made to use a key that is not in the registry.

---

## 9. Gaps

Severity: **Blocker** means the affected endpoint or capability cannot be implemented correctly or completely without a decision. The "Suggested resolution" column is input for ratification and is **not** part of the frozen content.

### 9.1 Closed by M2.1

| ID | Decision | Applied in |
|---|---|---|
| OG-01 | `tenant_id` column added; one chain per tenant | §3.1, §3.3 C1, §2.1 |
| OG-02 | `sequence` column (UInt64, monotonic per tenant); per-tenant serialized appends | §3.1, §3.3 C2 |
| OG-03 | SHA-256 over `ts, actor, action, payload, prev_hash`, JCS-serialized; genesis = SHA-256("GENESIS") | §3.3 C3, C4 |
| OG-04 | HRA holds the private key off-service; versioned keys rotated every 90 days; registry in `specs/TRUST_ANCHORS.md`; S2 takes `key_id` | §6.2, §6.3, §2.2 S1/S2 |
| OG-05 | Lowercase hex for signature and public key; signed content = JCS of `{context, nonce, timestamp, message}` | §6.4, §6.7 |
| OG-06 | JWT with EdDSA; claims `tenant_id`, `role`, `sub` mapped to OPA `user.*` | §4.1, §3.5 |
| OG-09 | A1, S1, S2 fail-closed; A2, A3 fail-open | §2.1, §5.5 |

Leftovers of the closed gaps are carried into OG-14 to OG-19 below.

### 9.2 Open

| ID | Gap | Why it matters | Severity | Suggested resolution |
|---|---|---|---|---|
| OG-07 | Role model and policy granularity: only `admin` exists; no action or resource-type dimension; precedence between `allow` and `deny` is undefined; the tenant that S1 and S2 are evaluated against is undefined. | Non-admins can never act; all endpoints share one rule. | High | Add roles and an action field to input; define `deny` as veto or informational; bind S1/S2 to the caller's tenant. |
| OG-08 | Rate-limit parameters and keying: `capacity`, `refill_rate`, `refill_interval` values; subject scheme (tenant, user, IP, endpoint); expiry of idle keys; clock source for caller-supplied `now` across API instances; time unit. | Limits are unenforceable without values; clock skew affects refill math. | High | Assign per-endpoint-class values; key by `tenant_id` plus endpoint; use a single time source. |
| OG-10 | Research snippets are defective as written. The Lua snippet has indexing errors (for example `tonumber(ARGV)[1]`, `capacity[1]`) and would not run; the chain-break SQL uses a correlated subquery whose support and performance in ClickHouse the research does not validate, and it must be rewritten for per-tenant `sequence` ordering. | Implementing the snippets verbatim would fail or perform badly. | High | Treat §3.3 and §5.3 as normative; validate and correct the snippets at implementation. |
| OG-11 | Enforcing immutability. The research relies on the engine choice; it does not cover database privileges, retention locks or backups that prevent modification or deletion. | A privileged actor could still alter data, and `sequence` uniqueness is not enforced by the database. | High | Define access controls and backup/retention protections for `audit_log`. |
| OG-12 | Business purpose and domain resources; path and `/v1` naming; range semantics for `from`/`to`; `breaks[].reason` values; pagination; payload format; error-body shape; HTTP status mapping. | Provisional wording in §2 may change. | Medium | Ratify or amend §2 in the next revision. |
| OG-13 | Non-functional requirements: relative order of rate limiting and authorization, availability and HA of OPA, ClickHouse, Redis and HRA, TLS, deployment, observability and alerting. | Not decidable from the sources. | Medium | Add an NFR section after the Blockers are closed. |
| OG-14 | Interface to HRA: how the API service requests a signature (protocol, authentication, timeouts); whether the service or HRA builds the signed content (this spec assumes the service); behavior when HRA is unreachable. | With the key off-service, S1 cannot work until this exists. | Blocker | Specify the HRA request/response contract and its failure behavior. |
| OG-15 | Trust anchors registry operation: `specs/TRUST_ANCHORS.md` does not exist yet; its record format and `key_id` format; how and when the service loads it; who may change it; handling of retired or revoked keys and of overlap after each 90-day rotation; the response for an unknown `key_id` (provisionally `valid = false`). | S2 trusts whatever the registry says, so its integrity is the trust root. | Blocker | Define format, loading, change control and retirement rules; populate with real keys from HRA. |
| OG-16 | Replay protection policy: where seen nonces are stored, for how long, and the timestamp tolerance window. S2 currently checks the signature only. | The signed content carries a nonce and timestamp that nothing enforces. | High | Define a nonce store with a TTL matching the tolerance window. |
| OG-17 | JWT validation and key distribution: token issuer, audience and expiry rules, token lifetime and revocation, where the JWT verification keys come from (and whether they are separate from HRA's), the set of valid `role` values, `sub` format. | Authorization trusts these claims entirely. | Blocker | Define issuer, validation rules and a JWT key source. |
| OG-18 | Append serialization and sequence mechanics: lock versus queue, its backing store (and its interplay with Redis outages), timeouts and failure behavior, recovery of the chain tail after a crash, first `sequence` value, whether gaps are allowed, and whether `tenant_id` and `sequence` should join the ClickHouse sort key. | A1 correctness and performance depend on it. | High | Choose a mechanism; define tail recovery from the stored chain; decide the first value and gap policy. |
| OG-19 | Hash input details: the JSON form and precision of `ts` when hashed (the column is one-second DateTime); `tenant_id` and `sequence` are not hash inputs under C3; re-anchoring the chain once TTL removes its oldest rows. | Implementations could hash differently; unhashed fields are not covered by tamper detection. | Medium | Fix a `ts` form; consider hashing `tenant_id` and `sequence`; define a retained anchor value for expired parts. |

---

## 10. Amendment log

### 10.1 Revisions

| Rev | Date | Change |
|---|---|---|
| 1 | 2026-11-11 | M2 initial freeze from the four research files. Gaps OG-01 to OG-13 opened. |
| 2 | 2026-11-11 | M2.1: decisions for OG-01 to OG-06 and OG-09 applied; new gaps OG-14 to OG-19; §4 gained an authentication section; a cross-reference to endpoint binding was corrected (§4.6 became §4.7). |

### 10.2 Derived items introduced in rev 2

These follow from the M2.1 decisions but were not stated in them. Each can be reversed without affecting the decisions.

| Item | Where |
|---|---|
| Audit operations act only on the caller's tenant; no tenant parameter | §2.1 |
| `actor` is the JWT `sub` | §2.2 A1, §3.1 |
| Chain order and predecessor are defined by `sequence`, not `ts` | §2.2 A3, §3.3 C6 |
| Verification also recomputes each row's `hash` | §3.3 C6 |
| Breaks carry `sequence` and a `reason` | §2.2 A3 |
| Hash values are lowercase hex | §3.3 C3 |
| Only EdDSA tokens are accepted | §4.1 |
| The service builds the signed content; S1 returns `nonce` and `timestamp` | §2.2 S1, §6.5 |
| Unknown `key_id` yields `valid = false` | §2.2 S2, §6.6 |
| New signatures use the newest key version | §6.2 |
| A2 and A3 never return 503 for rate-limit reasons | §2.3 |
