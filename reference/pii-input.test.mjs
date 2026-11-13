import test from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { InputValidationError, validateContactForm, createContactWriter } from './pii-input.mjs';

const contact = () => ({ fullName: 'Example Person', email: 'example@example.test' });

function rejects(input, field) {
  assert.throws(() => validateContactForm(input), error => {
    assert.ok(error instanceof InputValidationError);
    assert.equal(error.code, 'INVALID_CONTACT_FORM');
    if (field !== undefined) assert.equal(error.field, field);
    assert.equal(error.message, 'Invalid contact form');
    return true;
  });
}

test('normalizes supported names and email domains, preserves email local case', () => {
  const value = validateContactForm({ fullName: "  E\u0301lodie   O’Neil  ", email: 'First.Last+web@EXAMPLE.TEST' });
  assert.equal(value.fullName, 'Élodie O’Neil');
  assert.equal(value.email, 'First.Last+web@example.test');
  assert.equal(value.phone, null);
  assert.ok(Object.isFrozen(value));
  assert.equal(validateContactForm({ fullName: 'Иван Петров', email: 'x@bücher.example' }).email,
    'x@xn--bcher-kva.example');
});

test('rejects SQL/shell/HTML syntax in constrained name and phone fields', () => {
  for (const name of ["Robert'); DROP TABLE contacts;--", '$(id)', '`whoami`', '<script>x</script>', 'A|B', 'A\nB']) {
    rejects({ ...contact(), fullName: name }, 'fullName');
  }
  for (const phone of ['+1;id', '12345', '+0', '+12\r\nBcc:x', '+1234567890123456']) {
    rejects({ ...contact(), phone }, 'phone');
  }
  assert.equal(validateContactForm({ ...contact(), phone: '+12025550123' }).phone, '+12025550123');
});

test('validates email profile without blacklisting valid address punctuation', () => {
  assert.equal(validateContactForm({ ...contact(), email: "o'neil+tag@example.test" }).email,
    "o'neil+tag@example.test");
  for (const email of ['a@@example.test', '.a@example.test', 'a..b@example.test', 'a@localhost',
    'a@example.test/path', 'a@example.test:80', 'a@example.test\r\nBcc:x@y.test',
    'a@-bad.example', 'a@example..test', `${'a'.repeat(65)}@example.test`]) {
    rejects({ ...contact(), email }, 'email');
  }
});

test('rejects unexpected types, unknown/mass-assignment fields and prototype keys', () => {
  for (const input of [null, [], 1, 'x', { email: 'a@b.test' }, { fullName: 'Example' },
    { ...contact(), isAdmin: true }, JSON.parse('{"fullName":"Example","email":"a@b.test","__proto__":{}}'),
    { ...contact(), email: ['a@b.test'] }, { ...contact(), phone: 123 }, { ...contact(), message: null }]) {
    rejects(input);
  }
  rejects(Object.assign(Object.create({ isAdmin: true }), contact()));
  assert.equal(validateContactForm(Object.assign(Object.create(null), contact())).fullName, 'Example Person');
});

test('rejects accessors without invoking them and ignores no hidden/symbol fields', () => {
  let called = false;
  const input = contact();
  Object.defineProperty(input, 'message', { enumerable: true, get() { called = true; return 'x'; } });
  rejects(input, 'message');
  assert.equal(called, false);
  const hidden = contact();
  Object.defineProperty(hidden, 'message', { value: 'x', enumerable: false });
  rejects(hidden, 'message');
  rejects({ ...contact(), [Symbol('extra')]: 'x' });
});

test('bounds text work, Unicode scalars and control characters', () => {
  rejects({ ...contact(), fullName: 'A'.repeat(101) }, 'fullName');
  rejects({ ...contact(), message: 'x'.repeat(4001) }, 'message');
  rejects({ ...contact(), message: 'x'.repeat(2001) }, 'message');
  for (const text of ['x\0y', 'x\u0085y', 'x\u202ey', 'x\u2066y', 'x\ud800y']) {
    rejects({ ...contact(), message: text }, 'message');
  }
  assert.equal(validateContactForm({ ...contact(), message: 'x\r\ny' }).message, 'x\ny');
  assert.equal(validateContactForm({ ...contact(), message: '🙂'.repeat(2000) }).message.length, 4000);
});

test('stores hostile-looking message text as SQL data with no second statement execution', t => {
  const database = new DatabaseSync(':memory:');
  t.after(() => database.close());
  database.exec('CREATE TABLE contacts (id INTEGER PRIMARY KEY, full_name TEXT NOT NULL, email TEXT NOT NULL, phone TEXT, message TEXT)');
  const write = createContactWriter(database);
  const message = "'); DROP TABLE contacts;--\n$(touch /tmp/owned)\n<script>alert(1)</script>";
  write({ ...contact(), message });
  write({ ...contact(), message: 'SELECT is also an ordinary word here.' });
  const rows = database.prepare('SELECT message FROM contacts ORDER BY id').all();
  assert.equal(rows.length, 2);
  assert.equal(rows[0].message, message);
  assert.equal(rows[1].message, 'SELECT is also an ordinary word here.');
  assert.throws(() => write({ ...contact(), isAdmin: true }), InputValidationError);
  assert.equal(database.prepare('SELECT COUNT(*) AS count FROM contacts').get().count, 2);
});

test('validation errors do not echo submitted personal data', () => {
  const privateValue = 'private-user@example.test\ninvalid';
  try { validateContactForm({ ...contact(), email: privateValue }); assert.fail('Expected rejection'); }
  catch (error) {
    assert.ok(error instanceof InputValidationError);
    assert.equal(JSON.stringify(error).includes(privateValue), false);
    assert.equal(error.stack.includes(privateValue), false);
  }
});
