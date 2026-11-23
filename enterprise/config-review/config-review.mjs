import { createHash } from 'node:crypto';

export const RULE_IDS = Object.freeze([
  'approval-disabled', 'shell-unrestricted', 'remote-execution', 'instruction-authority',
  'instruction-unicode', 'credential-access', 'mcp-unpinned', 'mcp-plaintext',
  'mcp-http', 'artifact-agent-state',
]);
const id = /^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}(?![\s\S])/;
const logicalPath = /^[a-zA-Z0-9][a-zA-Z0-9_./-]{0,159}(?![\s\S])/;
const sha = /^[a-f0-9]{64}(?![\s\S])/;
const digest = value => createHash('sha256').update(value).digest('hex');
const etag = value => `"sha256-${digest(value)}"`;
function requireValue(condition) { if (!condition) throw new Error('unsupported-input'); }
function shape(value, keys) {
  requireValue(value !== null && typeof value === 'object' && !Array.isArray(value));
  requireValue(Object.keys(value).length === keys.length && keys.every(k => Object.hasOwn(value, k)));
}
function choice(value, choices) { requireValue(choices.includes(value)); }
function list(value, max = 100) { requireValue(Array.isArray(value) && value.length <= max); }
function text(value, max = 65536) { requireValue(typeof value === 'string' && Buffer.byteLength(value) <= max); }
function time(value) { requireValue(Number.isSafeInteger(value) && value >= 0); }
function path(value) {
  text(value, 160); requireValue(logicalPath.test(value) && !value.includes('//') &&
    !value.split('/').some(p => p === '.' || p === '..' || p === ''));
}
function parse(value) {
  text(value, 1048576);
  const parsed = JSON.parse(value), stack = [];
  // JSON.parse supplies grammar validation; this token pass rejects duplicate
  // decoded object keys (including escaped aliases) before last-wins normalization.
  for (const token of value.matchAll(/"(?:[^"\\]|\\[\s\S])*"|[{}\[\]]/g)) {
    const s = token[0];
    if (s === '{') stack.push(new Set());
    else if (s === '[') stack.push(null);
    else if (s === '}' || s === ']') stack.pop();
    else if (/^\s*:/.test(value.slice(token.index + s.length))) {
      const keys = stack.at(-1), key = JSON.parse(s);
      requireValue(keys instanceof Set && !keys.has(key)); keys.add(key);
    }
  }
  return parsed;
}
function boundedTree(value, depth = 0, count = { n: 0 }) {
  requireValue(depth <= 12 && ++count.n <= 20000);
  if (value && typeof value === 'object') for (const child of Object.values(value)) boundedTree(child, depth + 1, count);
}

// Binds exact serialized bytes, including trusted policy and the evaluation clock.
export function inputETag(snapshotJson, policyJson, now) {
  text(snapshotJson, 1048576); text(policyJson, 1048576); time(now);
  return etag(JSON.stringify(['agent-config-review/1', snapshotJson, policyJson, now]));
}

function configuration(value, add) {
  shape(value, ['approvals', 'shell', 'hooks', 'mcp', 'artifacts']);
  choice(value.approvals, ['enabled', 'disabled']); choice(value.shell, ['scoped', 'unrestricted']);
  if (value.approvals === 'disabled') add('approval-disabled');
  if (value.shell === 'unrestricted') add('shell-unrestricted');
  list(value.hooks); for (const h of value.hooks) {
    shape(h, ['source', 'execute']); choice(h.source, ['local', 'remote']);
    requireValue(typeof h.execute === 'boolean');
    if (h.source === 'remote' && h.execute) add('remote-execution');
  }
  list(value.mcp); for (const m of value.mcp) {
    shape(m, ['launcher', 'pin', 'tokenStorage', 'transport']);
    choice(m.launcher, ['package', 'image', 'fixed']);
    choice(m.tokenStorage, ['none', 'reference', 'plaintext']); choice(m.transport, ['stdio', 'https', 'http']);
    requireValue(m.pin === null || typeof m.pin === 'string');
    if (typeof m.pin === 'string') text(m.pin, 128);
    const pinned = m.launcher === 'image' ? /^sha256:[a-f0-9]{64}(?![\s\S])/.test(m.pin ?? '') :
      /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-[a-zA-Z0-9.-]+)?(?![\s\S])/.test(m.pin ?? '');
    if (m.launcher !== 'fixed' && !pinned) add('mcp-unpinned');
    if (m.tokenStorage === 'plaintext') add('mcp-plaintext');
    if (m.transport === 'http') add('mcp-http');
  }
  list(value.artifacts); for (const a of value.artifacts) {
    shape(a, ['included', 'class']); requireValue(typeof a.included === 'boolean');
    choice(a.class, ['application', 'agent-home', 'transcript', 'worktree']);
    if (a.included && a.class !== 'application') add('artifact-agent-state');
  }
}

function instructions(content, add) {
  // Narrow review heuristics, not semantic instruction understanding or data flow.
  if (/\b(?:override|ignore|bypass)\b[^.\n]{0,60}\b(?:rules|policy|instructions)\b|\b(?:conceal|hide)\b[^.\n]{0,60}\b(?:actions|user)\b|\b(?:skip|disable)\b[^.\n]{0,40}\bconfirmation\b/i.test(content)) add('instruction-authority');
  if (/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f\u00ad\u034f\u061c\u180e\u200b-\u200f\u2028-\u202e\u2060-\u206f\ufeff]/u.test(content)) add('instruction-unicode');
  if (/\b(?:read|open|access|extract)\b[^.\n]{0,80}\b(?:credential stores?|password stores?|ssh (?:keys?|material)|cloud credential(?:s| files?)?)\b/i.test(content)) add('credential-access');
  if (/\b(?:download|fetch)\b[^.\n]{0,80}\b(?:execute|run)\b/i.test(content)) add('remote-execution');
}

/** Pure offline review. Both JSON strings are data; policy must come from a trusted external owner. */
export function reviewConfiguration(snapshotJson, policyJson, now, expectedInputETag) {
  let inputTag = null;
  const finish = result => {
    const body = { schema: 'agent-config-review/1', inputETag: inputTag, ...result };
    return { ...body, resultETag: etag(JSON.stringify(body)) };
  };
  try {
    inputTag = inputETag(snapshotJson, policyJson, now);
    if (expectedInputETag !== inputTag) return finish({ status: 'incomplete', checkState: 'stale-input', findings: [] });
    const snapshot = parse(snapshotJson), policy = parse(policyJson);
    boundedTree(snapshot); boundedTree(policy);
    shape(snapshot, ['profile', 'files']); requireValue(snapshot.profile === 'normalized-agent-config/1');
    shape(policy, ['owner', 'scope', 'review', 'validUntil', 'ruleActions', 'exceptions']);
    for (const key of ['owner', 'scope', 'review']) requireValue(typeof policy[key] === 'string' && id.test(policy[key]));
    time(policy.validUntil); requireValue(policy.validUntil > now);
    shape(policy.ruleActions, RULE_IDS); for (const action of Object.values(policy.ruleActions)) choice(action, ['block', 'review']);
    list(policy.exceptions);
    for (const e of policy.exceptions) {
      shape(e, ['ruleId', 'fileSha256', 'owner', 'scope', 'review', 'validUntil']);
      choice(e.ruleId, RULE_IDS); requireValue(typeof e.fileSha256 === 'string' && sha.test(e.fileSha256));
      requireValue(e.owner === policy.owner && e.scope === policy.scope && typeof e.review === 'string' && id.test(e.review));
      time(e.validUntil); requireValue(e.validUntil > now && e.validUntil <= policy.validUntil);
    }
    list(snapshot.files); requireValue(snapshot.files.length > 0);
    const seen = new Set(), findings = [];
    for (const f of snapshot.files) {
      shape(f, ['path', 'kind', 'content']); path(f.path); requireValue(!seen.has(f.path)); seen.add(f.path);
      choice(f.kind, ['configuration', 'instructions', 'documentation']); text(f.content);
      const matches = new Set();
      if (f.kind === 'configuration') configuration(parse(f.content), rule => matches.add(rule));
      if (f.kind === 'instructions') instructions(f.content, rule => matches.add(rule));
      for (const ruleId of RULE_IDS.filter(r => matches.has(r))) {
        const excepted = policy.exceptions.some(e => e.ruleId === ruleId && e.fileSha256 === digest(f.content));
        findings.push({ file: f.path, ruleId, severity: ruleId === 'instruction-unicode' ? 'medium' : 'high',
          checkState: excepted ? 'accepted-exception' : policy.ruleActions[ruleId] === 'block' ? 'blocked' : 'review-required' });
      }
    }
    findings.sort((a, b) => a.file < b.file ? -1 : a.file > b.file ? 1 : RULE_IDS.indexOf(a.ruleId) - RULE_IDS.indexOf(b.ruleId));
    const status = findings.some(f => f.checkState === 'blocked') ? 'blocked' :
      findings.some(f => f.checkState === 'review-required') ? 'review-required' : findings.length ? 'exceptions-present' : 'no-findings';
    return finish({ status, checkState: 'complete-known-profile', findings });
  } catch {
    return finish({ status: 'incomplete', checkState: 'unsupported-input', findings: [] });
  }
}
