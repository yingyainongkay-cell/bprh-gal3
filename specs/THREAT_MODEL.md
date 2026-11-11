# THREAT_MODEL — GAL-3 (BPRH/SEOS)

| | |
|---|---|
| Milestone | M2 — Spec Freeze |
| Date | 2026-11-11 |
| Role | ARCHITECT |
| Companion | `FROZEN_SPEC_GAL3.md` (referred to below as "the spec"; `OG-nn` are its Open Gaps) |

## 1. Basis and method

Mitigations listed under **Research-backed mitigations** come only from the four research files and are cited as `[file › section]`. Impact and likelihood ratings are the ARCHITECT's qualitative assessment and are not derived from research. Items under **Follow-ups for ratification** go beyond the research; they are suggestions and are not frozen.

**Assumptions and trust boundaries**

- The boundary between callers and the API service is untrusted. Callers may be authenticated users of another tenant.
- OPA, ClickHouse and Redis are internal components assumed to be authentic. Operators with privileged access to ClickHouse are treated as a possible insider threat for R2.
- The authentication mechanism is unspecified (OG-06), so identity attributes reaching OPA are assumed trustworthy for this model; if they are not, R1 worsens.

## 2. Summary

| ID | Risk | Asset | Impact | Likelihood | Primary mitigations (research-backed) | Open gaps |
|---|---|---|---|---|---|---|
| R1 | Cross-tenant data leak | Tenant data, audit records | Critical | Medium | `tenant_id` equality before any grant; default deny; deny reason; `opa test` edge cases | OG-01, OG-06, OG-07 |
| R2 | Audit log tampering | Integrity of audit history | High | Low–Medium | Append-only MergeTree; per-row hash chain; chain-break detection; whole-part TTL drops | OG-02, OG-03, OG-11 |
| R3 | Rate limit bypass | Availability, abuse resistance | Medium | High | Atomic Lua token bucket; capacity-bounded bursts; low per-key memory | OG-08, OG-09 |
| R4 | Signature forgery | Authenticity of signed data | Critical | Low | RFC 8032 Ed25519 via PyNaCl; fixed 64-byte length; test vectors; single encoder | OG-04, OG-05 |
| R5 | Redis failure mode | Rate-limiter availability and safety | High | Medium | Explicit fail-closed vs fail-open policy | OG-08, OG-09, OG-13 |

---

## R1 — Cross-tenant data leak

**Description.** A user of tenant A reads or writes data belonging to tenant B.

**Attack scenarios**
- A caller submits a request for a resource whose tenant differs from their own.
- A policy rule is added that grants access without first checking tenant equality.
- A caller manipulates the value used as `resource.tenant_id`.
- Audit queries return rows from several tenants because the table carries no tenant attribute.

**Research-backed mitigations**
1. Tenant isolation is keyed on `tenant_id`: every granting rule must check `input.user.tenant_id == input.resource.tenant_id` before it grants. [opa-patterns.md › Tenant Isolation Pattern]
2. Default deny: anything not explicitly allowed is refused. [opa-patterns.md › Allow/Deny Pattern]
3. A dedicated deny rule produces the reason "cross-tenant access denied" for tenant mismatches. [opa-patterns.md › Allow/Deny Pattern]
4. Policy tests cover tenant mismatch and differing roles, run with `opa test ./policies/`; `opa check --strict` and `opa fmt --rego-v1` run in CI. [opa-patterns.md › Testing with opa test, OPA and Rego v1]

**Residual risk**
- The audit table has no tenant column, so isolation of audit data cannot be enforced or tested (OG-01).
- The policy has no action dimension and only one role (OG-07).
- Trust in `user` attributes depends on the undefined authentication mechanism (OG-06).

**Follow-ups for ratification (not frozen).** Source `resource.tenant_id` from the stored record, never from request input. Decide whether 403 responses should disclose the deny message, since it confirms a resource exists in another tenant.

---

## R2 — Audit log tampering

**Description.** Someone modifies, deletes, reorders or fabricates audit records without detection.

**Attack scenarios**
- Altering a row's `action` or `payload` after the fact.
- Deleting a row, or inserting one in the middle of history.
- Rewriting a row and recomputing every later hash so the chain still links.
- Removing the most recent rows.
- Abusing partition or TTL mechanics to drop data early.

**Research-backed mitigations**
1. MergeTree is used because it is append-only and has no dedup, unlike ReplacingMergeTree, which can replace rows. [clickhouse-audit-schema.md › MergeTree vs ReplacingMergeTree]
2. Each row stores `prev_hash` and `hash`, so altering or removing a row breaks linkage with its neighbour. [clickhouse-audit-schema.md › Hash-Chain Audit Table]
3. A chain-break query finds rows whose `prev_hash` differs from the preceding row's `hash`; it is exposed as endpoint A3. [clickhouse-audit-schema.md › Query Pattern: Detect Chain Break]
4. Retention is a 7-year TTL with `ttl_only_drop_parts=1` and monthly partitions, so expiry removes whole parts only. [clickhouse-audit-schema.md › TTL Policy, Partition Strategy]

**Residual risk**
- A hash chain alone does not prove authenticity: an attacker who can write to the table and knows the hash method can recompute the whole chain. The research does not link the chain to Ed25519 signatures or any external anchor.
- The detection query only examines rows that exist, so truncation of the newest rows is invisible to it.
- Rows with identical timestamps make ordering ambiguous, causing false breaks, and concurrent appends can fork the chain (OG-02).
- The hash definition, first-row value and post-TTL anchor are unspecified (OG-03).
- The research relies on the engine choice for immutability and covers no access controls (OG-11).

**Follow-ups for ratification (not frozen).** Consider signing periodic chain heads with the Ed25519 mechanism, or storing them outside ClickHouse; restrict write privileges on `audit_log` to append-only.

---

## R3 — Rate limit bypass

**Description.** A caller exceeds intended request rates, or avoids the limiter altogether.

**Attack scenarios**
- Concurrent requests race the limiter to consume more than the allowed tokens.
- The caller spreads requests across identities or keys, if the limiter keys on something the caller can vary.
- Clock disagreement between API instances skews refill computation, because `now` is supplied by the caller of the script.
- The caller exploits the full-bucket start to burst up to `capacity`.
- The caller induces Redis failure to trigger fail-open behavior (see R5).

**Research-backed mitigations**
1. The read-decide-update sequence is a Lua script run with `EVAL`, which makes it atomic and prevents race conditions. [redis-rate-limit.md › Lua Script for Atomic Token Bucket]
2. Token bucket caps bursts at `capacity` and sustained rate at `refill_rate` per `refill_interval`. [redis-rate-limit.md › Lua Script for Atomic Token Bucket]
3. One hash per key keeps memory low, so the limiter itself is hard to exhaust at the stated 1000 req/s. [redis-rate-limit.md › Performance at 1000 req/s]
4. Fail-closed on critical endpoints prevents bypass during an outage. [redis-rate-limit.md › Fail-Closed vs Fail-Open]

**Residual risk**
- The subject key scheme, parameter values and clock source are undefined (OG-08).
- Which endpoints are critical is undefined (OG-09).
- The research snippet is defective and must not be copied verbatim (OG-10).

**Follow-ups for ratification (not frozen).** Key limits by tenant plus endpoint rather than a caller-controlled value; use one authoritative time source for `now`; expire idle keys.

---

## R4 — Signature forgery

**Description.** An invalid or attacker-created signature is accepted as genuine, or a legitimate signature is attributed to the wrong data or key.

**Attack scenarios**
- A verification bug accepts a bad signature.
- Encoding mismatch (hex vs raw bytes) makes the verifier check different bytes than were signed.
- Malformed inputs of the wrong length reach the verifier.
- An attacker supplies their own public key to endpoint S2 and obtains `valid = true` for a message they signed.
- The sign endpoint (S1) is used as a signing oracle by an unauthorized or abusive caller.
- A valid signature is replayed in a different context.
- The private key is compromised.

**Research-backed mitigations**
1. Use the RFC 8032 algorithm through the PyNaCl library; do not implement the primitive. [ed25519-rfc8032.md › RFC 8032 Status, PyNaCl API]
2. The verify call raises BadSignatureError on an invalid signature, mapped to `valid = false`. [ed25519-rfc8032.md › PyNaCl API]
3. Signatures are a fixed 64 bytes with no padding, which supports strict length checking. [ed25519-rfc8032.md › Common Pitfalls]
4. Implementations must pass the RFC 8032 §7.1 test vectors. [ed25519-rfc8032.md › Test Vectors]
5. One agreed encoder and correct passing of message and signature address the documented pitfalls. [ed25519-rfc8032.md › Common Pitfalls]
6. Authorization (default deny, tenant isolation) and rate limiting apply to S1 and S2 like any endpoint. [opa-patterns.md; redis-rate-limit.md]

**Residual risk**
- Key custody, rotation and public-key trust are undefined, so `valid = true` establishes only consistency, not trust (OG-04).
- The encoding and the signed-content structure, including replay protection, are undecided (OG-05).

**Follow-ups for ratification (not frozen).** Verify against a registry of trusted keys rather than caller-supplied ones; include context and a nonce or timestamp in signed content.

---

## R5 — Redis failure mode

**Description.** Redis becomes unavailable, slow or loses state, and the rate limiter either blocks legitimate traffic or stops limiting.

**Attack scenarios**
- A genuine outage turns fail-closed endpoints into a full denial of service.
- An attacker degrades Redis to open a window on fail-open endpoints.
- A restart loses bucket state, so every key starts with a full bucket.
- An endpoint is misclassified, leaving a sensitive operation fail-open.

**Research-backed mitigations**
1. Failure behavior is an explicit, named choice: fail-closed denies every request when Redis is down; fail-open allows every request. [redis-rate-limit.md › Fail-Closed vs Fail-Open]
2. Research recommendation: fail-closed for critical endpoints, fail-open for non-critical ones. [redis-rate-limit.md › Fail-Closed vs Fail-Open]

**Residual risk**
- No endpoint has been classified (OG-09), so the recommendation cannot yet be applied.
- Persistence, replication and high availability of Redis are not covered (OG-13).
- Behavior on state loss is not covered (OG-08).
- Monitoring and alerting for limiter outages are not covered (OG-13).

**Follow-ups for ratification (not frozen).** Classify every endpoint explicitly, with A1, S1 and S2 treated as critical candidates; define alerting for limiter unavailability.

---

## 3. Coverage check

All five risks requested for M2 are covered: cross-tenant data leak (R1), audit log tampering (R2), rate limit bypass (R3), signature forgery (R4) and Redis failure mode (R5). Every R-level residual risk points to an Open Gap in the spec; closing the six Blockers (OG-01 to OG-06) removes the largest unmitigated exposures.
