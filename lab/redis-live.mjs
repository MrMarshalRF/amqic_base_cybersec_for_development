// Explicit synthetic loopback lab only. Never starts or configures Redis.
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { createRedisRateLimiter } from '../reference/admission.mjs';

assert.ok(process.env.AMQIC_REDIS_LAB_PORT, 'Set AMQIC_REDIS_LAB_PORT to a purpose-built isolated loopback Redis');
const port = Number(process.env.AMQIC_REDIS_LAB_PORT);
assert.ok(Number.isInteger(port) && port > 0 && port <= 65535, 'Invalid lab port');
// Public synthetic credential for the isolated disposable fixture, never production.
const limiter = createRedisRateLimiter({ host: '127.0.0.1', port, password: 'synthetic-lab-only-password', prefix: `amqic:lab:${randomBytes(8).toString('hex')}:`, limit: 2, windowMs: 2000 });
const results = await Promise.all(Array.from({ length: 8 }, () => limiter.check('synthetic-subject')));
if (results.some(result => result.reason === 'unavailable')) {
  console.error('NOT RUN: loopback Redis unavailable or incompatible; no live Redis evidence.');
  process.exitCode = 2;
} else {
  assert.equal(results.filter(result => result.allowed).length, 2);
  assert.deepEqual(results.map(result => result.count).sort((a, b) => a - b), [1, 2, 3, 4, 5, 6, 7, 8]);
  assert.ok(results.every(result => result.retryAfterMs >= 0 && result.retryAfterMs <= 2000));
  await new Promise(resolve => setTimeout(resolve, 2100));
  const reset = await limiter.check('synthetic-subject');
  assert.equal(reset.allowed, true);
  assert.equal(reset.count, 1);
  console.log('PASS: real loopback Redis atomic concurrent limits and expiry reset (synthetic keys, 2000 ms TTL).');
}
