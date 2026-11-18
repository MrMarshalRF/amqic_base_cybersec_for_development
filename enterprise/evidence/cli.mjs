import { mkdirSync, realpathSync, writeFileSync } from 'node:fs';
import { dirname, isAbsolute, join, relative, resolve, sep } from 'node:path';
import { exportEvidence, readBoundedFile, renderMarkdown, verifyEvidenceSignature } from './evidence.mjs';

try {
  const [action, ...args] = process.argv.slice(2);
  if (args.length !== 3 || args.some(value => value === '')) throw new Error('Invalid evidence CLI arguments');
  if (action === 'export') {
    const [repository, report, output] = args;
    if (!isAbsolute(repository) || !isAbsolute(output)) throw new Error('Absolute paths required');
    const root = realpathSync(repository);
    const destination = resolve(output);
    const parent = realpathSync(dirname(destination));
    const rel = relative(root, parent);
    if (rel === '' || !(isAbsolute(rel) || rel === '..' || rel.startsWith('..' + sep))) {
      throw new Error('Evidence output must be outside the repository');
    }
    const bundle = exportEvidence(root, report);
    const markdown = renderMarkdown(bundle);
    mkdirSync(destination, { mode: 0o700 });
    writeFileSync(join(destination, 'evidence.json'), JSON.stringify(bundle, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
    writeFileSync(join(destination, 'evidence.md'), markdown, { flag: 'wx', mode: 0o600 });
  } else if (action === 'verify') {
    const [bundle, key, signature] = args;
    if (!verifyEvidenceSignature(readBoundedFile(bundle), readBoundedFile(key, 4096), readBoundedFile(signature, 64))) {
      throw new Error('Detached evidence signature rejected');
    }
    process.stdout.write('Detached evidence signature verified.\n');
  } else throw new Error('Unsupported evidence command');
} catch {
  // Exceptions from untrusted reports and file APIs can contain private strings.
  process.stderr.write('Evidence operation rejected. See enterprise/evidence/README.md.\n');
  process.exitCode = 1;
}
