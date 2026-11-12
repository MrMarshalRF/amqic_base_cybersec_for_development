#!/usr/bin/env node
// Human terminal CLI. Exported primitives exist for synthetic tests only.
import { createCipheriv, createDecipheriv, randomBytes, scryptSync } from 'node:crypto';
import { createReadStream, closeSync, constants, fstatSync, fsyncSync, lstatSync, linkSync, openSync, readSync, unlinkSync, writeSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { emitKeypressEvents } from 'node:readline';

const MAGIC = Buffer.from('AMQICENC1');
const HEADER_SIZE = MAGIC.length + 16 + 12;
const TAG_SIZE = 16;
const N = 32768;
const R = 8;
const P = 1;

function derive(password, salt) {
  return scryptSync(password, salt, 32, { N, r: R, p: P, maxmem: 64 * 1024 * 1024 });
}

export function encryptBytes(bytes, password) {
  const header = Buffer.concat([MAGIC, randomBytes(16), randomBytes(12)]);
  const key = derive(password, header.subarray(MAGIC.length, MAGIC.length + 16));
  try {
    const cipher = createCipheriv('aes-256-gcm', key, header.subarray(MAGIC.length + 16));
    cipher.setAAD(header);
    return Buffer.concat([header, cipher.update(bytes), cipher.final(), cipher.getAuthTag()]);
  } finally {
    key.fill(0);
  }
}

function writeAll(descriptor, bytes) {
  let offset = 0;
  while (offset < bytes.length) offset += writeSync(descriptor, bytes, offset);
}

export async function transform(mode, input, output, password) {
  if (!['encrypt', 'decrypt'].includes(mode) || !Buffer.isBuffer(password) || password.length === 0) throw Error('invalid operation');
  input = resolve(input);
  output = resolve(output);
  if (input === output || !lstatSync(input).isFile() || lstatSync(input).isSymbolicLink()) throw Error('regular input required');
  // temp and final are on the same filesystem; link publication never overwrites.
  const temporary = resolve(dirname(output), `.amqic-${randomBytes(16).toString('hex')}.partial`);
  const descriptor = openSync(temporary, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL, 0o600);
  let key;
  let inputDescriptor;
  try {
    inputDescriptor = openSync(input, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
    const inputInfo = fstatSync(inputDescriptor);
    if (!inputInfo.isFile()) throw Error('regular input required');
    const length = inputInfo.size;
    let header;
    let cipher;
    let start;
    let end;
    if (mode === 'encrypt') {
      header = Buffer.concat([MAGIC, randomBytes(16), randomBytes(12)]);
      key = derive(password, header.subarray(MAGIC.length, MAGIC.length + 16));
      cipher = createCipheriv('aes-256-gcm', key, header.subarray(MAGIC.length + 16));
      writeAll(descriptor, header);
      start = 0;
      end = length - 1;
    } else {
      if (length < HEADER_SIZE + TAG_SIZE) throw Error('truncated envelope');
      header = Buffer.alloc(HEADER_SIZE);
      if (readSync(inputDescriptor, header, 0, HEADER_SIZE, 0) !== HEADER_SIZE || !header.subarray(0, MAGIC.length).equals(MAGIC)) throw Error('unsupported envelope');
      key = derive(password, header.subarray(MAGIC.length, MAGIC.length + 16));
      cipher = createDecipheriv('aes-256-gcm', key, header.subarray(MAGIC.length + 16));
      const tag = Buffer.alloc(TAG_SIZE);
      if (readSync(inputDescriptor, tag, 0, TAG_SIZE, length - TAG_SIZE) !== TAG_SIZE) throw Error('truncated envelope');
      cipher.setAuthTag(tag);
      start = HEADER_SIZE;
      end = length - TAG_SIZE - 1;
    }
    cipher.setAAD(header);
    if (end >= start) {
      const stream = createReadStream(input, { fd: inputDescriptor, autoClose: false, start, end });
      for await (const chunk of stream) writeAll(descriptor, cipher.update(chunk));
    }
    writeAll(descriptor, cipher.final());
    if (mode === 'encrypt') writeAll(descriptor, cipher.getAuthTag());
    const after = fstatSync(inputDescriptor);
    if (inputInfo.size !== after.size || inputInfo.mtimeMs !== after.mtimeMs || inputInfo.ctimeMs !== after.ctimeMs) throw Error('input changed');
    fsyncSync(descriptor);
    linkSync(temporary, output);
  } finally {
    key?.fill(0);
    if (inputDescriptor !== undefined) closeSync(inputDescriptor);
    closeSync(descriptor);
    unlinkSync(temporary);
  }
}

export async function hiddenPassword(prompt) {
  if (!process.stdin.isTTY || !process.stdout.isTTY) throw Error('human terminal required');
  emitKeypressEvents(process.stdin);
  const previousRaw = process.stdin.isRaw;
  process.stdin.setRawMode(true);
  process.stdin.resume();
  return new Promise((resolvePassword, reject) => {
    let value = '';
    const finish = (error) => {
      process.stdin.removeListener('keypress', handle);
      process.stdin.setRawMode(previousRaw);
      process.stdin.pause();
      process.stdout.write('\n');
      if (error) reject(error);
      else resolvePassword(Buffer.from(value, 'utf8'));
      value = '';
    };
    const handle = (text, key = {}) => {
      if (key.ctrl && key.name === 'c') return finish(Error('cancelled'));
      if (key.name === 'return' || key.name === 'enter') return finish();
      if (key.name === 'backspace') value = [...value].slice(0, -1).join('');
      else if (text && !key.ctrl && !key.meta && !/[\x00-\x1f\x7f]/u.test(text)) value += text;
      if (value.length > 1024) finish(Error('password too long'));
    };
    process.stdin.on('keypress', handle);
    // The terminal and listener must be ready before the prompt invites input.
    try {
      process.stdout.write(prompt);
    } catch (error) {
      finish(error);
    }
  });
}

export async function confirmedPassword(prompt = 'Archive password: ') {
  const first = await hiddenPassword(prompt);
  let second;
  try {
    second = await hiddenPassword('Repeat: ');
    if ([...first.toString('utf8')].length < 16 || !first.equals(second)) throw Error('use matching long password');
    return first;
  } catch (error) {
    first.fill(0);
    throw error;
  } finally {
    second?.fill(0);
  }
}

async function main() {
  const [mode, input, output, ...extra] = process.argv.slice(2);
  if (!['encrypt', 'decrypt'].includes(mode) || !input || !output || extra.length || !process.stdin.isTTY || !process.stdout.isTTY) throw Error('human terminal required');
  const password = mode === 'encrypt' ? await confirmedPassword() : await hiddenPassword('Archive password: ');
  try {
    await transform(mode, input, output, password);
    process.stdout.write(JSON.stringify({ status: 'completed', operation: mode }) + '\n');
  } finally {
    password.fill(0);
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch(() => {
    process.stderr.write('{"status":"refused_or_failed","detail":"preserve originals; reconcile output locally"}\n');
    process.exitCode = 1;
  });
}
