import { createHash } from 'node:crypto';

const identifier = value => typeof value === 'string' && /^[a-zA-Z0-9_.:-]{1,128}$/.test(value);
const deny = () => ({ granted: false });

// Use a dedicated SQLite connection to the same database in every worker.
// verifyPurchase is a trusted server adapter. readPolicy must be synchronous.
export function createBillingOfferGuard(db, { verifyPurchase, readPolicy, clock = Date.now }) {
  db.exec(`
    CREATE TABLE IF NOT EXISTS billing_offer_claims (
      token_hash TEXT PRIMARY KEY NOT NULL,
      account_id TEXT NOT NULL,
      campaign TEXT NOT NULL,
      product_id TEXT NOT NULL,
      base_plan_id TEXT NOT NULL,
      offer_id TEXT NOT NULL,
      expires_at INTEGER NOT NULL,
      UNIQUE (account_id, campaign)
    ) STRICT;
  `);
  const find = db.prepare('SELECT * FROM billing_offer_claims WHERE token_hash = ?');
  const insert = db.prepare('INSERT INTO billing_offer_claims VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT DO NOTHING');

  return async function claim(request) {
    if (request === null || typeof request !== 'object') return deny();
    const { accountId, campaign, purchaseToken } = request;
    if (!identifier(accountId) || !identifier(campaign) ||
        typeof purchaseToken !== 'string' || !/^[!-~]{1,4096}$/.test(purchaseToken)) return deny();

    try {
      const purchase = await verifyPurchase(purchaseToken);
      const now = clock();
      if (!Number.isSafeInteger(now) || now < 0) return deny();
      const policy = readPolicy(accountId, campaign, now);
      if (policy?.eligible !== true ||
          purchase?.accountId !== accountId || purchase.state !== 'active' || purchase.testPurchase !== false ||
          !Number.isSafeInteger(purchase.expiresAt) || purchase.expiresAt <= now ||
          !Number.isSafeInteger(policy.maxDurationMs) || policy.maxDurationMs <= 0 ||
          !['productId', 'basePlanId', 'offerId'].every(key => identifier(policy[key]) && policy[key] === purchase[key])) return deny();

      const tokenHash = createHash('sha256').update(purchaseToken).digest('hex');
      const expiry = Math.min(now + policy.maxDurationMs, purchase.expiresAt);
      // One write arbitrates both uniqueness rules across SQLite connections.
      // Subsequent reads cannot change the immutable claim or extend its lifetime.
      const issued = insert.run(tokenHash, accountId, campaign, policy.productId, policy.basePlanId, policy.offerId, expiry).changes === 1;
      const saved = find.get(tokenHash);
      if (!saved || saved.account_id !== accountId || saved.campaign !== campaign ||
          saved.product_id !== policy.productId || saved.base_plan_id !== policy.basePlanId || saved.offer_id !== policy.offerId ||
          saved.expires_at <= now) return deny();
      return { granted: true, issued, expiresAt: Math.min(saved.expires_at, purchase.expiresAt) };
    } catch {
      return deny();
    }
  };
}
