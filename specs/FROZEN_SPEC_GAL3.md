# FROZEN_SPEC_GAL3 — GAL-3 (BPRH/SEOS) Technical Specification

| | |
|---|---|
| Milestone | M2 — Spec Freeze |
| Status | FROZEN. Items in §9 (Open Gaps) are explicitly **not** frozen. |
| Date | 2026-11-11 |
| Role | ARCHITECT |
| Companion files | `THREAT_MODEL.md`, `openapi.yaml` |

---

## 0. How to read this spec

### 0.1 Source material

This spec is based only on four research files, all accessed 2026-11-11. They were delivered together in a single attachment; the file names below are the ones cited throughout.

| Short name | File | Covers |
|---|---|---|
| OPA | `opa-patterns.md` | Rego v1, allow/deny, tenant isolation, `opa test` |
| ED25519 | `ed25519-rfc8032.md` | RFC 8032, PyNaCl API, test vectors, pitfalls, JWT/EdDSA |
| CLICKHOUSE | `clickhouse-audit-schema.md` | MergeTree vs ReplacingMergeTree, hash-chain table, TTL, chain-break query, partitions |
| REDIS | `redis-rate-limit.md` | Token bucket, Lua atomicity, fail-closed/open, FastAPI, throughput |

Citation format: `[file › section]`, for example `[opa-patterns.md › Tenant Isolation Pattern]`.

### 0.2 Statement classes

| Class | Meaning |
|---|---|
| **Adopted** | Taken directly from a research file. Cited. |
| **Derived** | Needed to make the spec complete and follows mechanically from research, with no alternative chosen. Marked *(Derived)*. |
| **Gap** | Not covered by research. Never filled by assumption. Listed in §9 as `OG-nn` and referenced where it bites. |

### 0.3 Freeze rules

1. No new design decisions. Where research is silent, the spec says so and points to §9.
2. No code. Policies, schemas and algorithms are specified as tables and prose. Snippets in the research files are referenced by section, not reproduced, and OG-10 records where they must not be treated as normative.
3. Self-contained. Everything needed to read this spec is in this spec; the research files are cited for provenance, not required to understand it.

---

## 1. System overview

### 1.1 Purpose

The research does not state a business purpose for GAL-3 (OG-12). What the research does define is a service composed of four capabilities:

1. **Tenant-isolated authorization**, decided by OPA policy with default deny. [opa-patterns.md › Allow/Deny Pattern, Tenant Isolation Pattern]
2. **Tamper-evident audit logging**, stored as an append-only, hash-chained ClickHouse table. [clickhouse-audit-schema.md › Hash-Chain Audit Table]
3. **Ed25519 signing and verification** per RFC 8032 using PyNaCl. [ed25519-rfc8032.md › PyNaCl API]
4. **Rate limiting**, using a Redis token bucket updated atomically by a Lua script. [redis-rate-limit.md › Lua Script for Atomic Token Bucket]

### 1.2 Scope

| In scope | Out of scope (not covered by research) |
|---|---|
| Authorization policy contract and tenant-isolation rules | Authentication mechanism and identity provider (OG-06) |
| Audit table, hash-chain rules, retention | Business domain resources beyond the four capabilities (OG-12) |
| Token-bucket algorithm and failure modes | Key management for signing (OG-04) |
| Sign and verify flow | Deployment topology, HA, TLS, observability (OG-13) |
| REST contract exposing the four capabilities | Pagination, API versioning policy, error-body standard (OG-12) |

### 1.3 Actors

| Actor | Description | Basis |
|---|---|---|
| Tenant admin | Authenticated user with `role` = `admin`, belonging to one tenant (`user.tenant_id`). The only role the research authorizes. | [opa-patterns.md › Allow/Deny Pattern] |
| Other tenant user | Authenticated user with any other role value. Denied by default. | [opa-patterns.md › Allow/Deny Pattern] (default deny) |
| Cross-tenant caller | Authenticated user whose `tenant_id` differs from the resource's. Always denied, with a reason message. | [opa-patterns.md › Tenant Isolation Pattern] |
| Operator / CI | Runs policy checks and tests in the pipeline. Not a runtime role. | [opa-patterns.md › OPA and Rego v1] |

How callers authenticate is not specified (OG-06).

### 1.4 Components

| Component | Role | Basis |
|---|---|---|
| API service | Hosts the REST endpoints; Python, with FastAPI middleware or dependencies | [redis-rate-limit.md › FastAPI Implementation]; PyNaCl is a Python library [ed25519-rfc8032.md] |
| OPA | Policy decision point; package `authz`, Rego v1 | [opa-patterns.md] |
| ClickHouse | Audit store; table `audit_log` | [clickhouse-audit-schema.md] |
| Redis | Rate-limit state store; Lua script executed with `EVAL` | [redis-rate-limit.md] |
| PyNaCl | Ed25519 signing and verification library | [ed25519-rfc8032.md › PyNaCl API] |

### 1.5 Request processing order *(Derived)*

1. The caller sends a request; the caller's identity is mapped to the OPA `input.user` object (mechanism: OG-06).
2. The rate-limit check runs before the handler. [redis-rate-limit.md › FastAPI Implementation]
3. The authorization decision is requested from OPA; anything other than `allow = true` is a denial (default deny).
4. The handler runs (audit append, audit query, chain verification, sign, or verify).
5. The response is returned.

Steps 2 and 3 must both succeed before step 4. Their relative order is not specified by research (OG-13).

---

## 2. API endpoints (REST)

The research defines capabilities, not endpoints. The inventory below is the **minimal set that exposes each capability once** *(Derived)*. Path names, the `/v1` prefix and parameter names are provisional wording (OG-12); the capabilities and fields they carry are not.

### 2.1 Endpoint inventory

| ID | Method | Path | Capability | Success | Research basis |
|---|---|---|---|---|---|
| A1 | POST | `/v1/audit/events` | Append an audit event to the hash chain | 201 | [clickhouse-audit-schema.md › Hash-Chain Audit Table] |
| A2 | GET | `/v1/audit/events` | Read audit events in a time range | 200 | [clickhouse-audit-schema.md › Partition Strategy] (time-range queries) |
| A3 | GET | `/v1/audit/chain/verification` | Detect hash-chain breaks in a time range | 200 | [clickhouse-audit-schema.md › Query Pattern: Detect Chain Break] |
| S1 | POST | `/v1/signatures/sign` | Sign a message with Ed25519 | 200 | [ed25519-rfc8032.md › PyNaCl API] |
| S2 | POST | `/v1/signatures/verify` | Verify an Ed25519 signature | 200 | [ed25519-rfc8032.md › PyNaCl API] |

Cross-cutting rules for every endpoint:

- **Authorization:** the OPA decision must be `allow = true` (§4.7).
- **Rate limiting:** a token is consumed per request (§5). The failure mode when Redis is unavailable is **unassigned** per endpoint (OG-09).

### 2.2 Request and response schemas

**A1 — POST `/v1/audit/events`**

| Direction | Field | Type | Notes |
|---|---|---|---|
| Request | `action` | string | Maps to `audit_log.action` |
| Request | `payload` | string | Maps to `audit_log.payload`; opaque string, content format not specified (OG-12) |
| Response 201 | `ts` | date-time | Server-assigned |
| Response 201 | `actor` | string | Populated from the authenticated principal *(Derived)*; identifier not specified (OG-06) |
| Response 201 | `action`, `payload` | string | Echo of stored values |
| Response 201 | `prev_hash`, `hash` | string, exactly 64 chars | Chain linkage; computation not specified (OG-03) |

**A2 — GET `/v1/audit/events`**

| Direction | Field | Type | Notes |
|---|---|---|---|
| Query | `from` | date-time, required | Range start, inclusive (provisional, OG-12) |
| Query | `to` | date-time, required | Range end, exclusive (provisional, OG-12) |
| Response 200 | `events` | array of audit event | Same fields as the A1 response. Tenant scoping of results is unresolved (OG-01). |

**A3 — GET `/v1/audit/chain/verification`**

| Direction | Field | Type | Notes |
|---|---|---|---|
| Query | `from`, `to` | date-time, required | As A2. The predecessor of the first row in range is the latest row before `from`. |
| Response 200 | `intact` | boolean | `true` when `breaks` is empty *(Derived)* |
| Response 200 | `breaks` | array | One item per row whose `prev_hash` differs from the preceding row's `hash` |
| Response 200 | `breaks[].ts`, `.actor`, `.prev_hash`, `.hash` | as stored | The four columns the research query returns |

**S1 — POST `/v1/signatures/sign`**

| Direction | Field | Type | Notes |
|---|---|---|---|
| Request | `message` | string | Encoding not decided (OG-05) |
| Response 200 | `signature` | string | 64 raw bytes before encoding; fixed length per research. Encoding: OG-05 |
| Response 200 | `public_key` | string | The verify key matching the signing key *(Derived)*; identification scheme: OG-04 |

**S2 — POST `/v1/signatures/verify`**

| Direction | Field | Type | Notes |
|---|---|---|---|
| Request | `message` | string | Same encoding as S1 |
| Request | `signature` | string | Same encoding as S1 |
| Request | `public_key` | string | The verify key to check against *(Derived: verification needs message, signature and verify key)* |
| Response 200 | `valid` | boolean | `false` when the library reports a bad signature *(Derived from the BadSignatureError behavior)* |

Meaning of `valid = true`: the signature is consistent with this message and this key. It says nothing about whether the key is trusted (OG-04).

### 2.3 Error responses

Status codes use standard HTTP semantics. They are **not** from research (OG-12).

| Status | Condition |
|---|---|
| 400 | Malformed request |
| 401 | Caller not identified (OG-06) |
| 403 | OPA decision is not `allow`. May carry the deny message, for example "cross-tenant access denied". [opa-patterns.md › Allow/Deny Pattern] |
| 429 | Rate limiter returned `allowed = 0`. [redis-rate-limit.md › Lua Script for Atomic Token Bucket] |
| 503 | Rate-limit store unavailable on an endpoint configured fail-closed. [redis-rate-limit.md › Fail-Closed vs Fail-Open] |

---

## 3. Data models

### 3.1 ClickHouse table `audit_log`

| Column | Type | Meaning |
|---|---|---|
| `ts` | DateTime | Event time; first ordering key and partition source |
| `actor` | String | Who performed the action |
| `action` | String | What was done |
| `payload` | String | Event detail |
| `prev_hash` | FixedString(64) | `hash` of the preceding row in the chain |
| `hash` | FixedString(64) | This row's hash |

Table parameters [clickhouse-audit-schema.md › Hash-Chain Audit Table, Partition Strategy, TTL Policy]:

| Parameter | Value |
|---|---|
| Engine | MergeTree |
| ORDER BY | `(ts, actor)` |
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

| Rule | Statement |
|---|---|
| C1 | Every row stores `prev_hash` and `hash` to allow tamper detection. |
| C2 | The chain is intact iff every row's `prev_hash` equals the `hash` of the row immediately before it by `ts`. |
| C3 | Detection pattern: select rows whose `prev_hash` differs from the `hash` of the latest earlier row; report `ts`, `actor`, `prev_hash`, `hash`. |
| C4 | Rows are only inserted, never replaced (engine choice, §3.2). |
| C5 | Expiry happens only through TTL, at part granularity, after 7 years. |

[clickhouse-audit-schema.md › Hash-Chain Audit Table, Query Pattern: Detect Chain Break, TTL Policy]

Known defects in this model, recorded rather than silently fixed: OG-01 (no tenant column), OG-02 (ordering and concurrent appends), OG-03 (hash definition, first row, post-TTL anchor), OG-11 (enforcing immutability).

### 3.4 Redis rate-limit state

| Item | Specification |
|---|---|
| Key | One key per limited subject, passed to the script as its single key. The subject scheme is not specified (OG-08). |
| Structure | Hash with two fields: `tokens` and `last_refill` |

[redis-rate-limit.md › Lua Script for Atomic Token Bucket, Performance at 1000 req/s]

### 3.5 Policy documents (OPA)

| Document | Content |
|---|---|
| Input | `user.tenant_id`, `user.role`, `resource.tenant_id` |
| Output | `allow` (boolean, default `false`); `deny` (set of message strings) |

[opa-patterns.md › Allow/Deny Pattern]

### 3.6 Signing data

Inputs and outputs are `message`, `signature` (64 bytes) and the verify key. Nothing is persisted by the research design. Where signing keys live is OG-04.

---

## 4. Authorization policy (OPA Rego)

### 4.1 Engine and syntax

- OPA 1.0; Rego v1 is the default syntax. `if`, `contains` and `in` are built in; `import future.keywords` is not needed. [opa-patterns.md › OPA and Rego v1]
- Package name: `authz`. [opa-patterns.md › Allow/Deny Pattern]

### 4.2 Rules

| ID | Rule | Condition | Result |
|---|---|---|---|
| Z1 | Default | No rule matched | `allow = false` |
| Z2 | Allow | `user.tenant_id` equals `resource.tenant_id` **and** `user.role` equals `"admin"` | `allow = true` |
| Z3 | Deny reason | `user.tenant_id` differs from `resource.tenant_id` | `deny` contains "cross-tenant access denied" |
| Z4 | Tenant check first | Every rule that grants access | Must check tenant equality before granting, to prevent cross-tenant leaks |

[opa-patterns.md › Allow/Deny Pattern, Tenant Isolation Pattern]. The reference Rego for Z1–Z3 is in that file and is adopted unchanged.

### 4.3 Decision matrix

| Caller | Same tenant? | Role | `allow` | `deny` |
|---|---|---|---|---|
| Admin | Yes | `admin` | true | empty |
| Non-admin | Yes | other | false (default) | empty |
| Admin | No | `admin` | false | contains cross-tenant message |
| Non-admin | No | other | false | contains cross-tenant message |
| Any | Required attribute missing | any | false (default deny) | empty |

The last row follows from default deny and Rego's treatment of undefined values *(Derived)*.

### 4.4 Consequences of the adopted rules

1. No role other than `admin` is ever allowed.
2. The input has no action or method, so the policy cannot distinguish one endpoint from another. Under the frozen policy, every endpoint in §2.1 is reachable only by a same-tenant admin. Finer rules are OG-07.
3. `deny` is informational: `allow` does not consult it. How the enforcement point consumes `deny` (for example, as a veto) is not specified (OG-07).

### 4.5 Quality gates

| Gate | Command | Purpose |
|---|---|---|
| Strict check | `opa check --strict` | Run in CI |
| Format | `opa fmt --rego-v1` | Run in CI |
| Tests | `opa test ./policies/` | Test file kept separate from the policy; must cover allow, deny and edge cases (tenant mismatch, differing roles) |

[opa-patterns.md › OPA and Rego v1, Testing with opa test]

### 4.6 Endpoint binding *(Derived)*

Every endpoint in §2.1 requires `allow = true`. The source of `resource.tenant_id` for each endpoint cannot currently be defined, because the audit table has no tenant column (OG-01).

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

Research recommendation: fail-closed for critical endpoints, fail-open for non-critical ones. Which endpoints are critical is **not decided** (OG-09). [redis-rate-limit.md › Fail-Closed vs Fail-Open]

### 5.6 Integration and performance

- Integration: FastAPI middleware or dependency that calls the script through `redis.eval()` before the handler. [redis-rate-limit.md › FastAPI Implementation]
- Performance: the design target noted in research is 1000 req/s; token bucket needs low memory (one hash per key). [redis-rate-limit.md › Performance at 1000 req/s]

---

## 6. Signing and verification flow (Ed25519)

### 6.1 Standard and library

- RFC 8032 (EdDSA), January 2017, Proposed Standard; the primary reference for Ed25519. [ed25519-rfc8032.md › RFC 8032 Status]
- Library: PyNaCl, `nacl.signing`, with `SigningKey` (private) and `VerifyKey` (public); keys are based on a 32-byte seed. [ed25519-rfc8032.md › PyNaCl API]
- Variant: plain Ed25519. The research gives API guidance for no other variant, so the other variants listed in RFC 8032 are out of scope.

### 6.2 Sign flow (S1)

1. Authorization and rate-limit checks pass (§1.5).
2. Decode `message` using the single agreed encoding (OG-05).
3. Sign with the `SigningKey`; the signature is always 64 bytes. [ed25519-rfc8032.md › Common Pitfalls]
4. Encode the signature with the same encoding and return it with the matching `public_key`.

### 6.3 Verify flow (S2)

1. Authorization and rate-limit checks pass.
2. Decode `message`, `signature` and `public_key` using the single agreed encoding.
3. Reject signatures that are not 64 bytes *(Derived from the fixed length)*.
4. Verify with the `VerifyKey`, passing both message and signature correctly.
5. If the library raises BadSignatureError, return `valid = false`; otherwise `valid = true`.

[ed25519-rfc8032.md › PyNaCl API, Common Pitfalls]

### 6.4 Pitfalls adopted as requirements

| Pitfall | Requirement |
|---|---|
| Encoding: hex vs raw bytes | One encoder, stated explicitly and used identically on both sides (value undecided: OG-05) |
| Padding | None. Unlike RSA, signature length is fixed at 64 bytes |
| Verify arguments | Pass message and signature correctly to the verify call |

### 6.5 Conformance

The implementation must pass the Ed25519 test vectors in RFC 8032 §7.1. [ed25519-rfc8032.md › Test Vectors]

### 6.6 JWT note

If JWTs are used, EdDSA (RFC 8037) with Ed25519 is the research's reference; it is smaller and faster than RS256. Whether JWTs are used at all is undecided (OG-06). [ed25519-rfc8032.md › JWT with EdDSA vs Ed25519]

---

## 7. Traceability matrix

| Spec section | Research source |
|---|---|
| §2 A1–A3 | clickhouse-audit-schema.md (Hash-Chain Audit Table; Query Pattern; Partition Strategy) |
| §2 S1–S2 | ed25519-rfc8032.md (PyNaCl API) |
| §3.1–3.3 | clickhouse-audit-schema.md (all sections) |
| §3.4, §5 | redis-rate-limit.md (all sections) |
| §3.5, §4 | opa-patterns.md (all sections) |
| §6 | ed25519-rfc8032.md (all sections) |

---

## 8. Acceptance checks mandated by research

1. `opa check --strict`, `opa fmt --rego-v1` and `opa test ./policies/` pass in CI. [opa-patterns.md]
2. RFC 8032 §7.1 test vectors pass. [ed25519-rfc8032.md]
3. The chain-break detection pattern runs against the audit table and reports no breaks on untampered data. [clickhouse-audit-schema.md]
4. The rate-limit script is atomic and its failure mode matches the assigned class per endpoint. [redis-rate-limit.md]

---

## 9. Open Gaps

Severity: **Blocker** means the affected endpoint or capability cannot be implemented correctly or completely without a decision. The "Suggested resolution" column is input for ratification and is **not** part of the frozen content.

| ID | Gap | Why it matters | Severity | Suggested resolution |
|---|---|---|---|---|
| OG-01 | `audit_log` has no tenant column. | Tenant isolation cannot be enforced at the data layer; `resource.tenant_id` for audit rows has no source; unclear whether the chain is global or per tenant. | Blocker | Add a tenant identifier; decide global vs per-tenant chain. |
| OG-02 | Chain ordering. `ts` is DateTime (one-second resolution), ordering is `(ts, actor)`, and the research detection query compares strictly earlier `ts`. Concurrent appends are not serialized. | Rows sharing a timestamp make "previous row" ambiguous (false breaks); concurrent writers can fork the chain. | Blocker | Add a monotonic sequence or finer-grained time; serialize appends per chain. |
| OG-03 | Hash definition: algorithm, which fields are hashed and in what canonical form, text encoding of the 64 characters, the `prev_hash` of the very first row, and how the chain is re-anchored once TTL drops its oldest parts. | Two implementations would produce incompatible chains. | Blocker | Specify all four in a single normative paragraph. |
| OG-04 | Key management for Ed25519: who holds signing keys, storage, rotation, key identifiers, distribution of public keys, and whether the service should expose a sign endpoint at all. | S1 has no key source; S2 `valid` cannot assert trust. | Blocker | Decide key custody and a key registry before building S1/S2. |
| OG-05 | What is signed, and the encoding of message, signature and key (hex vs raw/other). Replay protection is not addressed. | Research flags encoding mismatch as a pitfall but picks none. | Blocker | Choose one encoder; define the signed-content structure including context binding. |
| OG-06 | Authentication and identity: how `user.tenant_id` and `user.role` reach OPA, the identifier used for `actor`, and whether JWT is used (and with which algorithm). | The whole authorization model depends on trusted identity attributes. | Blocker | Decide the authn mechanism; define the claims-to-input mapping. |
| OG-07 | Role model and policy granularity: only `admin` exists; no action or resource-type dimension; precedence between `allow` and `deny` is undefined. | Non-admins can never act; all endpoints share one rule. | High | Add roles and an action field to input; define `deny` as veto or informational. |
| OG-08 | Rate-limit parameters and keying: `capacity`, `refill_rate`, `refill_interval` values; subject scheme (tenant, user, IP, endpoint); expiry of idle keys; clock source for caller-supplied `now` across API instances; time unit. | Limits are unenforceable without values; clock skew affects refill math. | High | Assign per-endpoint-class values; key by tenant plus endpoint; use a single time source. |
| OG-09 | Classification of endpoints as critical or non-critical for fail-closed vs fail-open. | Redis failure behavior is undefined per endpoint. | High | Classify A1, S1, S2 and the rest explicitly. |
| OG-10 | Research snippets are defective as written. The Lua snippet has indexing errors (for example `tonumber(ARGV)[1]`, `capacity[1]`) and would not run; the chain-break SQL uses a correlated subquery whose support and performance in ClickHouse the research does not validate. | Implementing the snippets verbatim would fail or perform badly. | High | Treat §3.3 and §5.3 as normative; validate and correct the snippets at implementation. |
| OG-11 | Enforcing immutability. The research relies on the engine choice; it does not cover database privileges, retention locks or backups that prevent modification or deletion. | A privileged actor could still alter data. | High | Define access controls and backup/retention protections for `audit_log`. |
| OG-12 | Business purpose and domain resources; path and `/v1` naming; range semantics for `from`/`to`; pagination; payload format; error-body shape; HTTP status mapping. | Provisional wording in §2 may change. | Medium | Ratify or amend §2 in the next revision. |
| OG-13 | Non-functional requirements: relative order of rate limiting and authorization, availability and HA of OPA, ClickHouse and Redis, TLS, deployment, observability and alerting. | Not decidable from research. | Medium | Add an NFR section after the Blockers are closed. |
