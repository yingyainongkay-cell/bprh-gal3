# THREAT_MODEL — GAL-3 (BPRH/SEOS)

| | |
|---|---|
| Milestone | M2 — Spec Freeze, amended by M2.1 |
| Revision | 2 |
| Date | 2026-11-11 |
| Role | ARCHITECT |
| Companion | `FROZEN_SPEC_GAL3.md` rev 2 (referred to below as "the spec"; `OG-nn` are its gaps) |

## 1. Basis and method

Mitigations come from two sources and are labeled accordingly: **research-backed** ones cite `[file › section]`, and **decision-backed** ones cite `[M2.1 › OG-nn]`, the decisions the project owner supplied on 2026-11-11. Impact and likelihood ratings are the ARCHITECT's qualitative assessment and are not derived from either source. Items under **Follow-ups for ratification** go beyond both sources; they are suggestions and are not frozen.

**Assumptions and trust boundaries**

- The boundary between callers and the API service is untrusted. Callers may be authenticated users of another tenant.
- OPA, ClickHouse and Redis are internal components assumed to be authentic. Operators with privileged access to ClickHouse are treated as a possible insider threat for R2.
- HRA, which holds the signing key, is assumed trustworthy and reachable; its compromise is out of scope but noted under R4.
- Identity now comes from an EdDSA-signed JWT, but validation rules and key distribution are undefined (OG-17), so this model assumes tokens are only issued by a trusted party; if not, R1 worsens.

## 2. Summary

| ID | Risk | Asset | Impact | Likelihood | Primary mitigations | Open gaps |
|---|---|---|---|---|---|---|
| R1 | Cross-tenant data leak | Tenant data, audit records | Critical | Medium | `tenant_id` equality before any grant; default deny; per-tenant chain and tenant-scoped operations; signed-JWT identity | OG-07, OG-17 |
| R2 | Audit log tampering | Integrity of audit history | High | Low–Medium | Append-only MergeTree; per-tenant SHA-256 hash chain with JCS; sequence ordering; serialized appends; recomputing verification | OG-11, OG-18, OG-19 |
| R3 | Rate limit bypass | Availability, abuse resistance | Medium | High | Atomic Lua token bucket; capacity-bounded bursts; fail-closed on critical endpoints | OG-08 |
| R4 | Signature forgery | Authenticity of signed data | Critical | Low | Off-service key; registry-only verification; hex encoding; domain-separated signed content; key rotation | OG-14, OG-15, OG-16 |
| R5 | Redis failure mode | Rate-limiter availability and safety | High | Medium | Explicit fail-closed vs fail-open classification per endpoint | OG-08, OG-13, OG-18 |

---

## R1 — Cross-tenant data leak

**Description.** A user of tenant A reads or writes data belonging to tenant B.

**Attack scenarios**
- A caller submits a request for a resource whose tenant differs from their own.
- A policy rule is added that grants access without first checking tenant equality.
- A caller manipulates the value used as `resource.tenant_id`, or the claims used as `user.tenant_id`.
- Audit queries return rows from several tenants.

**Research-backed mitigations**
1. Tenant isolation is keyed on `tenant_id`: every granting rule must check `input.user.tenant_id == input.resource.tenant_id` before it grants. [opa-patterns.md › Tenant Isolation Pattern]
2. Default deny: anything not explicitly allowed is refused. [opa-patterns.md › Allow/Deny Pattern]
3. A dedicated deny rule produces the reason "cross-tenant access denied" for tenant mismatches. [opa-patterns.md › Allow/Deny Pattern]
4. Policy tests cover tenant mismatch and differing roles, run with `opa test ./policies/`; `opa check --strict` and `opa fmt --rego-v1` run in CI. [opa-patterns.md › Testing with opa test, OPA and Rego v1]

**Decision-backed mitigations**
5. The audit table carries `tenant_id` and each tenant has its own chain, so rows and their integrity checks are tenant-separated at the data layer. [M2.1 › OG-01]
6. Audit endpoints have no tenant parameter and request bodies never carry `tenant_id`; the tenant comes from the caller's token and `resource.tenant_id` from the server-side scope or stored row (spec §2.1, §4.7).
7. Identity attributes arrive as claims in a JWT signed with EdDSA, and only that algorithm is accepted, so a caller cannot choose their own tenant or role. [M2.1 › OG-06]

**Residual risk**
- If the JWT issuer or its keys are compromised, forged `tenant_id` claims defeat every tenant check (OG-17).
- The policy has no action dimension and only one role; S1 and S2 have no stored resource, so the tenant they are evaluated against is undefined (OG-07).

**Follow-ups for ratification (not frozen).** Decide whether 403 responses should disclose the deny message, since it confirms a resource exists in another tenant. Include `tenant_id` in the audit-table sort key so per-tenant scans stay isolated and fast.

---

## R2 — Audit log tampering

**Description.** Someone modifies, deletes, reorders or fabricates audit records without detection.

**Attack scenarios**
- Altering a row's `action` or `payload` after the fact.
- Deleting a row, or inserting one in the middle of a tenant's history.
- Rewriting a row and recomputing every later hash so the chain still links.
- Removing the most recent rows of a chain.
- Changing a row's `tenant_id` or `sequence`.
- Racing two appends for one tenant so the chain forks.
- Abusing partition or TTL mechanics to drop data early.

**Research-backed mitigations**
1. MergeTree is used because it is append-only and has no dedup, unlike ReplacingMergeTree, which can replace rows. [clickhouse-audit-schema.md › MergeTree vs ReplacingMergeTree]
2. Each row stores `prev_hash` and `hash`, so altering or removing a row breaks linkage with its neighbour. [clickhouse-audit-schema.md › Hash-Chain Audit Table]
3. A chain-break check is exposed as endpoint A3. [clickhouse-audit-schema.md › Query Pattern: Detect Chain Break]
4. Retention is a 7-year TTL with `ttl_only_drop_parts=1` and monthly partitions, so expiry removes whole parts only. [clickhouse-audit-schema.md › TTL Policy, Partition Strategy]

**Decision-backed mitigations**
5. A defined hash (SHA-256 over `ts, actor, action, payload, prev_hash`, serialized with RFC 8785 JCS) and a fixed genesis value remove ambiguity about what a valid chain is. [M2.1 › OG-03]
6. `sequence` gives each row an unambiguous position, and appends are serialized per tenant, which removes the same-second ordering ambiguity and the chain-fork race. [M2.1 › OG-02]
7. Verification recomputes each row's `hash`, so changing content without fixing its hash is caught, in addition to broken links (spec §3.3, rule C6; derived).
8. Per-tenant chains confine the effect of tampering and let each tenant verify only its own history. [M2.1 › OG-01]

**Residual risk**
- A hash chain alone does not prove authenticity: an attacker who can write to the table and knows the hash method can recompute a whole chain. Neither source links the chain to Ed25519 signatures or an external anchor.
- Removal of the newest rows of a chain is invisible to verification, which only examines rows that exist.
- `tenant_id` and `sequence` are not hash inputs, so a change to them is caught only indirectly through broken links (OG-19).
- The `ts` form used for hashing, and re-anchoring when TTL removes a chain's oldest rows, are unspecified (OG-19).
- The lock or queue mechanism, its failure behavior and tail recovery are undefined (OG-18).
- Nothing in either source stops a privileged actor from altering rows (OG-11).

**Follow-ups for ratification (not frozen).** Sign periodic chain heads with the Ed25519 mechanism or store them outside ClickHouse; hash `tenant_id` and `sequence` as well; restrict write privileges on `audit_log` to append-only.

---

## R3 — Rate limit bypass

**Description.** A caller exceeds intended request rates, or avoids the limiter altogether.

**Attack scenarios**
- Concurrent requests race the limiter to consume more than the allowed tokens.
- The caller spreads requests across identities or keys, if the limiter keys on something the caller can vary.
- Clock disagreement between API instances skews refill computation, because `now` is supplied by the caller of the script.
- The caller exploits the full-bucket start to burst up to `capacity`.
- The caller induces Redis failure to trigger fail-open behavior on A2 or A3 (see R5).

**Research-backed mitigations**
1. The read-decide-update sequence is a Lua script run with `EVAL`, which makes it atomic and prevents race conditions. [redis-rate-limit.md › Lua Script for Atomic Token Bucket]
2. Token bucket caps bursts at `capacity` and sustained rate at `refill_rate` per `refill_interval`. [redis-rate-limit.md › Lua Script for Atomic Token Bucket]
3. One hash per key keeps memory low, so the limiter itself is hard to exhaust at the stated 1000 req/s. [redis-rate-limit.md › Performance at 1000 req/s]
4. Fail-closed on critical endpoints prevents bypass during an outage. [redis-rate-limit.md › Fail-Closed vs Fail-Open]

**Decision-backed mitigations**
5. A1, S1 and S2 are classified fail-closed, so the writing and signing paths cannot be unthrottled by disrupting Redis. [M2.1 › OG-09]
6. Authenticated claims (`tenant_id`, `sub`) are now available as key material that callers cannot choose freely. [M2.1 › OG-06]

**Residual risk**
- The subject key scheme, parameter values and clock source are still undefined (OG-08).
- The research snippet is defective and must not be copied verbatim (OG-10).
- A2 and A3 are fail-open (see R5).

**Follow-ups for ratification (not frozen).** Key limits by `tenant_id` plus endpoint, and by `sub` where per-user limits matter; use one authoritative time source for `now`; expire idle keys.

---

## R4 — Signature forgery

**Description.** An invalid or attacker-created signature is accepted as genuine, or a legitimate signature is attributed to the wrong data, key or tenant.

**Attack scenarios**
- A verification bug accepts a bad signature.
- Encoding mismatch makes the verifier check different bytes than were signed.
- Malformed inputs of the wrong length reach the verifier.
- An attacker presents their own key to S2 to obtain `valid = true` for a message they signed.
- S1 is used as a signing oracle by an authorized-but-abusive caller.
- A valid signature is replayed, or reused in another tenant's context.
- The registry file is altered to add an attacker's key.
- A signing key is compromised or used past its rotation period.

**Research-backed mitigations**
1. Use the RFC 8032 algorithm through the PyNaCl library; do not implement the primitive. [ed25519-rfc8032.md › RFC 8032 Status, PyNaCl API]
2. The verify call raises BadSignatureError on an invalid signature, mapped to `valid = false`. [ed25519-rfc8032.md › PyNaCl API]
3. Signatures are a fixed 64 bytes with no padding, which supports strict length checking. [ed25519-rfc8032.md › Common Pitfalls]
4. Implementations must pass the RFC 8032 §7.1 test vectors. [ed25519-rfc8032.md › Test Vectors]
5. Authorization (default deny, tenant isolation) and rate limiting apply to S1 and S2 like any endpoint, both fail-closed. [opa-patterns.md; redis-rate-limit.md]

**Decision-backed mitigations**
6. The private key lives with HRA, off-service, so compromising the API service does not expose it. [M2.1 › OG-04]
7. S2 resolves `key_id` in a registry instead of accepting a caller-supplied public key, closing the attacker-key scenario. [M2.1 › OG-04]
8. Keys are versioned and rotated every 90 days, bounding the exposure window of any one key. [M2.1 › OG-04]
9. Lowercase hex is the single encoding for signature and public key, and signed content is canonical JCS JSON including a fixed `context`, so bytes are unambiguous and signatures from this service cannot be mistaken for other uses. [M2.1 › OG-05]
10. A `nonce` and `timestamp` are part of the signed content, giving a basis for replay defense. [M2.1 › OG-05]

**Residual risk**
- The registry becomes the trust root: whoever can edit `specs/TRUST_ANCHORS.md` or change how it is loaded can add a key that S2 will accept. Retired and revoked keys are undefined (OG-15).
- Nothing enforces the nonce or timestamp yet, so replay remains possible (OG-16).
- The signed content has no tenant or caller binding: a signature produced for one tenant verifies for any other, and the signature says nothing about who requested it. Any admin of any tenant can use S1 to sign arbitrary messages with the shared service key.
- The HRA interface, its authentication and its failure behavior are undefined (OG-14); compromise of HRA itself is out of scope.

**Follow-ups for ratification (not frozen).** Include `tenant_id` and `sub` in the signed content; define a nonce store and timestamp window; protect the registry with change control and an integrity check at load time.

---

## R5 — Redis failure mode

**Description.** Redis becomes unavailable, slow or loses state, and the rate limiter either blocks legitimate traffic or stops limiting.

**Attack scenarios**
- A genuine outage turns fail-closed endpoints into a denial of service, including audit appends.
- An attacker degrades Redis to open an unthrottled window on fail-open endpoints, in particular repeated chain verification, which is an expensive query.
- A restart loses bucket state, so every key starts with a full bucket.
- If the per-tenant append serializer is backed by Redis, an outage also stalls appends independently of the limiter.

**Research-backed mitigations**
1. Failure behavior is an explicit, named choice: fail-closed denies every request when Redis is down; fail-open allows every request. [redis-rate-limit.md › Fail-Closed vs Fail-Open]
2. Research recommendation: fail-closed for critical endpoints, fail-open for non-critical ones. [redis-rate-limit.md › Fail-Closed vs Fail-Open]

**Decision-backed mitigations**
3. Endpoints are classified: A1, S1 and S2 fail-closed (503); A2 and A3 fail-open. [M2.1 › OG-09]

**Residual risk**
- Because A1 is fail-closed, a Redis outage means no audit events can be recorded; callers must decide whether to retry, queue or drop them. This is undefined (OG-13).
- Because A3 is fail-open, an attacker who can degrade Redis gets unthrottled access to a query that scans a tenant's chain.
- Persistence, replication and high availability of Redis are not covered; behavior on state loss is not covered (OG-08, OG-13).
- The append serializer's backing store is not chosen, so its coupling to Redis is open (OG-18).
- Monitoring and alerting for limiter outages are not covered (OG-13).

**Follow-ups for ratification (not frozen).** Apply a local fallback limit on A3 while Redis is down; define an audit-append buffering policy for outages; define alerting for limiter unavailability.

---

## 3. Coverage check

All five risks requested for M2 are covered: cross-tenant data leak (R1), audit log tampering (R2), rate limit bypass (R3), signature forgery (R4) and Redis failure mode (R5). The M2.1 decisions close the largest exposures from revision 1 (no tenant column, ambiguous chain ordering, undefined hash, caller-supplied keys, unspecified authentication). The new Blockers OG-14, OG-15 and OG-17 now carry the biggest unmitigated risk, because they define the trust roots: the signing interface, the key registry and the JWT issuer.
