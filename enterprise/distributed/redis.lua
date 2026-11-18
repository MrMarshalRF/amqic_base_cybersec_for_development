-- One persistent key per tenant. The operator provisions it before admission.
local function bounded(x, low, high)
    return type(x) == 'number' and x >= low and x <= high and x == math.floor(x)
end
local function token(s)
    return type(s) == 'string' and #s >= 1 and #s <= 80 and s:match('^[a-zA-Z0-9_-]+$')
end
local function digest(s)
    return type(s) == 'string' and #s == 64 and s:match('^[0-9a-f]+$')
end
local generation, policy, operation, binding, proposed, risk = unpack(ARGV)
local window = tonumber(proposed)
if #KEYS ~= 1 or #ARGV ~= 6 or not token(generation) or not digest(policy)
    or not token(operation) or not digest(binding) or not bounded(window, 0, 10000000000)
    or (risk ~= 'normal' and risk ~= 'elevated') then
    return 'invalid_request'
end
local raw = redis.call('GET', KEYS[1])
if not raw then return 'unprovisioned' end
if #raw > 200000 or redis.call('PTTL', KEYS[1]) ~= -1 then return 'invalid_state' end
local ok, s = pcall(cjson.decode, raw)
if not ok or type(s) ~= 'table' or not token(s.generation) or not digest(s.policyDigest)
    or not bounded(s.windowMs, 1000, 3600000) or not bounded(s.normal, 1, 1000)
    or not bounded(s.elevatedCap, 0, s.normal) or not bounded(s.used, 0, s.normal)
    or not bounded(s.lastMs, 0, 9007199254740991)
    or not bounded(s.window, 0, 10000000000) or type(s.elevated) ~= 'boolean'
    or type(s.operations) ~= 'table' then
    return 'invalid_state'
end
if s.generation ~= generation or s.policyDigest ~= policy then return 'policy_mismatch' end
local length = 0
for id, df in pairs(s.operations) do
    if not token(id) or not digest(df) then return 'invalid_state' end
    length = length + 1
end
if length ~= s.used then return 'invalid_state' end

local t = redis.call('TIME')
local now = tonumber(t[1]) * 1000 + math.floor(tonumber(t[2]) / 1000)
if now < s.lastMs then return 'clock_rollback' end
local current = math.floor(now / s.windowMs)
if current ~= window then return 'window_changed' end
if current ~= s.window then
    s.used, s.elevated, s.operations = 0, false, {}
end
if s.operations[operation] then
    if s.operations[operation] == binding then return 'duplicate' end
    return 'conflict'
end

s.lastMs, s.window = now, current
s.elevated = s.elevated or risk == 'elevated'
local cap = s.elevated and s.elevatedCap or s.normal
local decision = 'rate_limited'
if s.used < cap then
    s.used = s.used + 1
    s.operations[operation] = binding
    decision = 'granted'
end
-- The only mutation in the script. Serialization failure leaves state intact.
redis.call('SET', KEYS[1], cjson.encode(s))
return decision
