import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import test from 'node:test';
import { createBillingOfferGuard } from './billing-offer.mjs';

const sku = { productId: 'demo-product', basePlanId: 'demo-plan', offerId: 'demo-offer' };
const purchase = { ...sku, accountId: 'demo-account', state: 'active', testPurchase: false, expiresAt: 1000 };
const claim = { accountId: 'demo-account', campaign: 'demo-campaign', purchaseToken: 'synthetic-token' };
const policy = { ...sku, eligible: true, maxDurationMs: 100 };

test('only authoritative matching, active and eligible purchases can grant a trial', async () => {
  const db = new DatabaseSync(':memory:');
  try {
    let record = purchase;
    let rule = policy;
    const grant = createBillingOfferGuard(db, {
      verifyPurchase: async () => record,
      readPolicy: () => rule,
      clock: () => 100,
    });
    assert.deepEqual(await grant(null), { granted: false });
    assert.deepEqual(await grant({}), { granted: false });
    for (const delta of [{ accountId: 'other' }, { offerId: 'hidden' }, { basePlanId: 'other' },
      { productId: 'other' }, { state: 'pending' }, { expiresAt: 100 }, { testPurchase: true }]) {
      record = { ...purchase, ...delta };
      assert.deepEqual(await grant(claim), { granted: false });
    }
    record = purchase;
    rule = { ...policy, eligible: false };
    assert.deepEqual(await grant(claim), { granted: false });
    rule = policy;
    assert.deepEqual(await grant(claim), { granted: true, issued: true, expiresAt: 200 });
    record = { ...purchase, accountId: 'second-account' };
    assert.deepEqual(await grant({ ...claim, accountId: record.accountId }), { granted: false });
    record = null;
    assert.deepEqual(await grant(claim), { granted: false });
  } finally { db.close(); }
});

test('two connections issue once, retries cannot extend, and a second token cannot reuse a campaign', async () => {
  const root = mkdtempSync(join(tmpdir(), 'billing-offer-'));
  const db1 = new DatabaseSync(join(root, 'claims.sqlite'));
  const db2 = new DatabaseSync(join(root, 'claims.sqlite'));
  try {
    let now = 100;
    const adapters = { verifyPurchase: async () => purchase, readPolicy: () => policy, clock: () => now };
    const a = createBillingOfferGuard(db1, adapters);
    const b = createBillingOfferGuard(db2, adapters);
    const results = await Promise.all([a(claim), b(claim)]);
    assert.equal(results.filter(result => result.issued).length, 1);
    assert.ok(results.every(result => result.granted && result.expiresAt === 200));
    now = 150;
    assert.deepEqual(await b(claim), { granted: true, issued: false, expiresAt: 200 });
    assert.deepEqual(await b({ ...claim, purchaseToken: 'second-token' }), { granted: false });
    assert.deepEqual(await b({ ...claim, campaign: 'other-campaign' }), { granted: false });
    now = 200;
    assert.deepEqual(await a(claim), { granted: false });
    assert.equal(db1.prepare('SELECT count(*) AS total FROM billing_offer_claims').get().total, 1);
  } finally {
    db2.close();
    db1.close();
    rmSync(root, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 });
  }
});
