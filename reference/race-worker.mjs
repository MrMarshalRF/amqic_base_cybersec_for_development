import { parentPort, workerData } from 'node:worker_threads';
import { SecurityCore, AccessDenied, syntheticTools } from './core.mjs';

const { database, now, request, barrier, mode } = workerData;
const core = new SecurityCore({ database, audience: 'synthetic-example', clock: () => now, tools: syntheticTools,
  captcha: { verify: () => false }, factors: { assertEnrollment: () => false, secretFor: () => undefined } });
parentPort.postMessage('ready');
const signal = new Int32Array(barrier);
for (;;) {
  const observed = Atomics.load(signal, 0);
  if (observed >= 3) break;
  Atomics.wait(signal, 0, observed);
}
try {
  const input = { ...request, body: Buffer.from(request.body) };
  if (mode === 'dispatch') parentPort.postMessage(core.dispatch(input));
  else {
    core.verifyRequest(input, 'records.remove');
    parentPort.postMessage('accepted');
  }
} catch (error) {
  if (!(error instanceof AccessDenied)) throw error;
  parentPort.postMessage('denied');
} finally { core.close(); }
