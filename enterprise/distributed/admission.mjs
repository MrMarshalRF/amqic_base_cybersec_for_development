import { readFileSync } from 'node:fs';

const redisScript = readFileSync(new URL('./redis.lua', import.meta.url), 'utf8');
const sql = 'SELECT amqic_quota.admit($1, $2, $3, $4, $5, $6, $7) AS status';
const token = /^[a-zA-Z0-9_-]{1,80}$/;
const digest = /^[a-f0-9]{64}$/;
const statuses = new Set([
  'granted', 'duplicate', 'conflict', 'rate_limited', 'clock_rollback',
  'window_changed', 'unprovisioned', 'policy_mismatch', 'invalid_request',
  'invalid_state', 'unknown'
]);

function result(status) {
  const safeStatus = statuses.has(status) ? status : 'unknown';
  return Object.freeze({ status: safeStatus, allowed: safeStatus === 'granted' });
}

function valid(x) {
  return x && typeof x.tenant === 'string' && token.test(x.tenant) &&
    typeof x.generation === 'string' && token.test(x.generation) &&
    typeof x.policyDigest === 'string' && digest.test(x.policyDigest) &&
    typeof x.operationId === 'string' && token.test(x.operationId) &&
    typeof x.bindingDigest === 'string' && digest.test(x.bindingDigest) &&
    Number.isSafeInteger(x.window) && x.window >= 0 && x.window <= 10_000_000_000 &&
    (x.risk === 'normal' || x.risk === 'elevated');
}

function adapter(dispatch) {
  return async input => {
    if (!valid(input)) return result('invalid_request');
    try {
      const { tenant, generation, policyDigest, operationId, bindingDigest, window, risk } = input;
      return result(await dispatch(tenant, [generation, policyDigest, operationId, bindingDigest, window, risk]));
    } catch {
      // A lost reply may follow a successful mutation. Callers only act on a
      // fresh grant and must reconcile business effects independently.
      return result('unknown');
    }
  };
}

export function postgresAdmission(client) {
  if (typeof client?.query !== 'function') throw new TypeError('PostgreSQL query client required');
  return adapter(async (tenant, args) => {
    const response = await client.query(sql, [tenant, ...args]);
    return response.rows?.length === 1 ? response.rows[0]?.status : undefined;
  });
}

export function redisAdmission(client) {
  if (typeof client?.eval !== 'function') throw new TypeError('Redis eval client required');
  return adapter((tenant, args) => client.eval(redisScript, {
    keys: ['amqic:quota:v1:' + tenant], arguments: args.map(String)
  }));
}
