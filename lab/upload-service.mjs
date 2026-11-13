import { createUploadStore } from '../reference/upload-pipeline.mjs';
import { createClamdScanner } from '../reference/clamd-client.mjs';

/** Real clamd is mandatory here. The web layer supplies an authenticated owner. */
export function createUploadService({ root, clamdHost, clamdPort, maxBytes = 1048576, scanTimeoutMs = 15000 } = {}) {
  return createUploadStore({ root, maxBytes, scanTimeoutMs, scanner: createClamdScanner({ host: clamdHost, port: clamdPort, maxBytes, timeoutMs: Math.max(1, Math.floor(scanTimeoutMs / 3)) }) });
}
