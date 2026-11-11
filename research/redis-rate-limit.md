markdown
# Redis Token Bucket vs Sliding Window for Rate Limiting

## Token Bucket vs Sliding Window

| Aspect | Token Bucket | Sliding Window |
|---|---|---|
| Burst | อนุญาต burst (สะสม token) | จำกัดตาม window ต่อเนื่อง |
| Memory | ต่ำ (counter + timestamp) | สูง (log ต่อ request) |
| Fairness | bias ไปที่ request แรก | fair กว่า (true rolling window) |
| Use case | API ที่ยอมรับ burst | API ที่ต้องการ fair-share |

## Lua Script for Atomic Token Bucket
ใช้ Lua script ผ่าน `EVAL` เพื่อให้ read-decide-update atomic — ป้องกัน race condition [38][39]

```lua
local key = KEYS
local capacity = tonumber(ARGV)
local refill_rate = tonumber(ARGV)
local refill_interval = tonumber(ARGV)
local now = tonumber(ARGV)
local bucket = redis.call('HMGET', key, 'tokens', 'last_refill')
local tokens = tonumber(bucket) or capacity
local last_refill = tonumber(bucket) or now
local time_passed = now - last_refill
local refills = math.floor(time_passed / refill_interval)
if refills > 0 then
  tokens = math.min(capacity, tokens + (refills * refill_rate))
  last_refill = last_refill + (refills * refill_interval)
end
local allowed = 0
if tokens >= 1 then
  tokens = tokens - 1
  allowed = 1
end
redis.call('HMSET', key, 'tokens', tokens, 'last_refill', last_refill)
return {allowed, tokens}
