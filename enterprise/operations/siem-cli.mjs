import { describeSiemBatch, exportSiemBatch } from './siem.mjs';
import { readBoundedFile } from '../evidence/evidence.mjs';

const MAX_INPUT_BYTES = 2 * 1024 * 1024;
const decode = new TextDecoder('utf-8', { fatal: true });
const readJson = (path, limit) => JSON.parse(decode.decode(readBoundedFile(path, limit)));
for (const stream of [process.stdout, process.stderr]) {
  stream.on('error', () => { process.exitCode = 2; });
}
const write = (stream, text) => new Promise((resolve, reject) => {
  stream.write(text, error => error ? reject(error) : resolve());
});

try {
  const [mode, entriesPath, bindingPath, expectedEtag, ...rest] = process.argv.slice(2);
  if (!entriesPath || !bindingPath || rest.length ||
      !((mode === 'describe' && expectedEtag === undefined) || (mode === 'export' && expectedEtag))) {
    throw new Error('Invalid usage');
  }
  const entries = readJson(entriesPath, MAX_INPUT_BYTES);
  const binding = readJson(bindingPath, 4096);
  if (mode === 'describe') {
    await write(process.stdout, JSON.stringify(describeSiemBatch(entries, binding)) + '\n');
  } else {
    const { ndjson, receipt } = exportSiemBatch(entries, binding, expectedEtag);
    await write(process.stdout, ndjson);
    await write(process.stderr, JSON.stringify(receipt) + '\n');
  }
} catch {
  // Arguments, input data and underlying errors can include private operational details.
  process.stderr.write('SIEM batch rejected or output failed.\n');
  process.exitCode = 2;
}
