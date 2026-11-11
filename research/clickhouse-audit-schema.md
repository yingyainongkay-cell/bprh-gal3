markdown
# ClickHouse Schema for Immutable Audit Logs

## MergeTree vs ReplacingMergeTree
- `MergeTree`: append-only log (audit) — ไม่มี dedup, ทุก insert เป็นแถวใหม่
- `ReplacingMergeTree`: upsert (มี version column) — dedup ระหว่าง merge, เหมาะกับ "latest state" [36][37]

สำหรับ audit log ที่ต้องการ immutability → ใช้ `MergeTree`

## Hash-Chain Audit Table
เก็บ `prev_hash` และ `hash` ต่อ row เพื่อตรวจจับ tampering:

```sql
CREATE TABLE audit_log (
  ts DateTime,
  actor String,
  action String,
  payload String,
  prev_hash FixedString(64),
  hash FixedString(64)
) ENGINE = MergeTree()
ORDER BY (ts, actor)
PARTITION BY toYYYYMM(ts)
