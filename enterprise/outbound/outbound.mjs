import { request as httpsRequest } from 'node:https';
import { lookup as dnsLookup } from 'node:dns/promises';
import { isIP } from 'node:net';

const MAX_BYTES = 1024 * 1024;
const MAX_ANSWERS = 32;
const MAX_CHUNKS = 4096;
const ID = /^[a-z][a-z0-9-]{0,63}$/;

function record(value, allowed) {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      ![Object.prototype, null].includes(Object.getPrototypeOf(value)) ||
      Reflect.ownKeys(value).some(key => !allowed.includes(key))) throw new TypeError('Invalid configuration or arguments');
}

function localPath(path) {
  // Deliberately narrow canonical profile: no URL parsing/normalization of input.
  return typeof path === 'string' && path.length <= 1024 &&
    /^\/(?:[A-Za-z0-9_-]+\/)*[A-Za-z0-9_-]*$/.test(path);
}

function hostname(value) {
  return typeof value === 'string' && value.length <= 253 && !isIP(value) &&
    value.includes('.') && /^[a-z0-9]+(?:[a-z0-9.-]*[a-z0-9])?$/.test(value) &&
    value.split('.').every(label => label.length <= 63 && /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(label)) &&
    /^[a-z][a-z0-9-]*$/.test(value.split('.').at(-1));
}

/** Conservative IPv4-only profile; no IPv6, mapped addresses or special-use ranges. */
export function isPublicIPv4(address) {
  if (isIP(address) !== 4) return false;
  const [a, b, c] = address.split('.').map(Number);
  if (a === 0 || a === 10 || a === 127 || a >= 224 ||
      (a === 100 && b >= 64 && b <= 127) ||
      (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && (b === 0 || b === 168 || (b === 88 && c === 99) ||
        (b === 31 && c === 196) || (b === 52 && c === 193) || (b === 175 && c === 48))) ||
      (a === 198 && (b === 18 || b === 19 || (b === 51 && c === 100))) ||
      (a === 203 && b === 0 && c === 113) || address === '168.63.129.16') return false;
  return true;
}

export class OutboundError extends Error {
  constructor(code) { super('Outbound request denied or failed'); this.name = 'OutboundError'; this.code = code; }
}

/** Trusted startup only. Never expose this factory or its adapters to model input. */
export function createOutboundClient(config) {
  record(config, ['endpoints', 'resolve', 'request']);
  const { endpoints, resolve = dnsLookup, request = httpsRequest } = config;
  if (!Array.isArray(endpoints) || !endpoints.length || endpoints.length > 64 ||
      typeof resolve !== 'function' || typeof request !== 'function') throw new TypeError('Invalid configuration or arguments');
  const catalog = new Map();
  for (const item of endpoints) {
    record(item, ['id', 'hostname', 'path', 'maxBytes', 'timeoutMs', 'contentType']);
    const { id, hostname: host, path, maxBytes, timeoutMs, contentType } = item;
    if (typeof id !== 'string' || !ID.test(id) || catalog.has(id) || !hostname(host) || !localPath(path) ||
        !Number.isInteger(maxBytes) || maxBytes < 1 || maxBytes > MAX_BYTES ||
        !Number.isInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 10_000 ||
        !['application/json', 'text/plain'].includes(contentType)) throw new TypeError('Invalid configuration or arguments');
    catalog.set(id, Object.freeze({ host, path, maxBytes, timeoutMs, contentType }));
  }
  return Object.freeze({
    get(id, options = {}) {
      // All validation happens before a resolver or transport is called.
      try {
        record(options, ['signal']);
        if (options.signal !== undefined && !(options.signal instanceof AbortSignal)) throw new TypeError();
        if (typeof id !== 'string' || !catalog.has(id)) throw new TypeError();
      } catch { return Promise.reject(new OutboundError('ARGUMENTS')); }
      const endpoint = catalog.get(id);
      const { signal } = options;
      return new Promise((fulfill, reject) => {
        let done = false, req, res, socket;
        const close = () => {
          // No upstream error objects/bytes are propagated to the caller.
          res?.destroy(); req?.destroy(); socket?.destroy();
        };
        const finish = (code, body) => {
          if (done) return;
          done = true;
          clearTimeout(timer);
          signal?.removeEventListener('abort', abort);
          close();
          if (code) reject(new OutboundError(code)); else fulfill(body);
        };
        const abort = () => finish('ABORTED');
        const timer = setTimeout(() => finish('TIMEOUT'), endpoint.timeoutMs);
        signal?.addEventListener('abort', abort, { once: true });
        if (signal?.aborted) { abort(); return; }
        // Deadline is already running, including asynchronous DNS resolution.
        Promise.resolve().then(() => {
          if (done) return null;
          return resolve(endpoint.host, { all: true, verbatim: true });
        }).then(answers => {
          if (done) return;
          if (!Array.isArray(answers) || !answers.length || answers.length > MAX_ANSWERS ||
              answers.some(answer => !answer || answer.family !== 4 || !isPublicIPv4(answer.address))) {
            finish('DESTINATION'); return;
          }
          const address = answers[0].address;
          const lookup = (name, options, callback) => {
            if (typeof options === 'function') { callback = options; options = {}; }
            if (done || name !== endpoint.host) { callback(new OutboundError('DESTINATION')); return; }
            if (options?.all) callback(null, [{ address, family: 4 }]);
            else callback(null, address, 4);
          };
          req = request({ protocol: 'https:', hostname: endpoint.host, port: 443,
            path: endpoint.path, method: 'GET', family: 4, lookup,
            servername: endpoint.host, rejectUnauthorized: true, agent: false,
            maxHeaderSize: 8192, headers: { accept: endpoint.contentType, 'accept-encoding': 'identity' } }, incoming => {
            res = incoming;
            res.on('error', () => finish('TRANSPORT'));
            if (done) { res.destroy(); return; }
            const headers = res.headers;
            const type = headers?.['content-type'];
            const length = headers?.['content-length'];
            if (res.statusCode !== 200 || typeof type !== 'string' ||
                type.split(';')[0].trim().toLowerCase() !== endpoint.contentType ||
                (headers['content-encoding'] !== undefined && headers['content-encoding'] !== 'identity') ||
                (length !== undefined && (typeof length !== 'string' || !/^(0|[1-9][0-9]{0,6})$/.test(length) || Number(length) > endpoint.maxBytes))) {
              finish('RESPONSE'); return;
            }
            const chunks = [];
            let bytes = 0, count = 0, ended = false;
            res.on('data', chunk => {
              if (done) return;
              if (!Buffer.isBuffer(chunk) || ++count > MAX_CHUNKS || chunk.length > endpoint.maxBytes - bytes) {
                finish('SIZE'); return;
              }
              bytes += chunk.length;
              chunks.push(Buffer.from(chunk));
            });
            res.on('aborted', () => finish('TRANSPORT'));
            res.on('close', () => { if (!ended) finish('TRANSPORT'); });
            res.on('end', () => {
              ended = true;
              if (done) return;
              if (res.complete === false || (length !== undefined && bytes !== Number(length))) finish('RESPONSE');
              else finish(null, Buffer.concat(chunks, bytes));
            });
          });
          req.on('error', () => finish('TRANSPORT'));
          req.on('socket', owned => { socket = owned; if (done) owned.destroy(); });
          if (done) { close(); return; }
          req.end();
        }).catch(() => finish('TRANSPORT'));
      });
    }
  });
}

/** Fixed application return destinations; unrelated to OIDC redirect_uri validation. */
export function createReturnRouteResolver(routes) {
  if (!Array.isArray(routes) || !routes.length || routes.length > 64) throw new TypeError('Invalid return routes');
  const catalog = new Map();
  for (const route of routes) {
    record(route, ['id', 'path']);
    if (typeof route.id !== 'string' || !ID.test(route.id) || catalog.has(route.id) || !localPath(route.path)) throw new TypeError('Invalid return routes');
    catalog.set(route.id, route.path);
  }
  return id => {
    if (typeof id !== 'string' || !catalog.has(id)) throw new TypeError('Unknown return route');
    return catalog.get(id);
  };
}
