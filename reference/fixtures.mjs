import { generateKeyPairSync } from 'node:crypto';
import { SecurityCore, syntheticTools } from './core.mjs';
import { canonical, hash, signRequest, totp } from './crypto.mjs';

// Synthetic adapters only. Never import this file into an application deployment.
export function fixture({ database = ':memory:', tools = syntheticTools, initialTime = 1800000000 } = {}) {
  let now = initialTime;
  const secret = Buffer.from('12345678901234567890');
  const pair = generateKeyPairSync('ed25519');
  const proofs = new Set();
  const core = new SecurityCore({ database, audience: 'synthetic-example', tools, clock: () => now,
    captcha: { verify: ({ proof, challenge }) => proofs.delete(challenge + ':' + proof) },
    factors: { assertEnrollment: ({ id, factorRef }) => id === 'user-1' && factorRef === 'factor-1',
      secretFor: ref => ref === 'factor-1' ? secret : undefined }
  });
  const provision = () => {
    core.provisionUser({ id: 'user-1', identity: 'person@example.test', password: 'synthetic-long-password',
      factorRef: 'factor-1', scopes: ['records.remove'] });
    core.registerKey({ keyId: 'example-key', userId: 'user-1', publicKey: pair.publicKey.export({ type: 'spki', format: 'pem' }), scopes: ['records.remove'] });
  };
  const captchaProof = ticket => {
    // Emulates an independently verified single-use provider result tied to this challenge.
    const proof = 'synthetic-provider-result';
    proofs.add(hash(ticket) + ':' + proof);
    return proof;
  };
  const code = () => totp(secret, Math.floor(now / 30));
  const login = () => {
    const a = core.login('person@example.test', 'synthetic-client');
    const b = core.password(a.ticket, 'synthetic-long-password', 'synthetic-client');
    const c = core.captcha(b.ticket, captchaProof(b.ticket), 'synthetic-client');
    return core.secondFactor(c.ticket, code(), 'synthetic-client').session;
  };
  const request = body => signRequest(pair.privateKey, { keyId: 'example-key', method: 'POST', target: '/tools/call',
    audience: 'synthetic-example', timestamp: now, body: Buffer.from(canonical(body)) });
  return { core, pair, secret, provision, login, request, code, captchaProof,
    now: () => now, advance: (seconds = 30) => { now += seconds; } };
}

