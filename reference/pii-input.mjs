import { domainToASCII } from 'node:url';

const FIELDS = new Set(['fullName', 'email', 'phone', 'message']);
const CONTROL = /[\u0000-\u001f\u007f-\u009f]/u;
const TEXT_CONTROL = /[\u0000-\u0009\u000b-\u001f\u007f-\u009f]/u;
const BIDI_OVERRIDE = /[\u202a-\u202e\u2066-\u2069]/u;
const SURROGATE = /\p{Cs}/u;
const NAME = /^[\p{L}\p{M}]+(?:[ .'\u2019-][\p{L}\p{M}]+)*\.?$/u;
const EMAIL_LOCAL = /^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+$/u;
const DOMAIN_LABEL = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/u;

export class InputValidationError extends Error {
  constructor(field = null) {
    super('Invalid contact form');
    this.name = 'InputValidationError';
    this.code = 'INVALID_CONTACT_FORM';
    this.field = field;
  }
}

function fail(field = null) { throw new InputValidationError(field); }

function normalizedText(value, field, max, multiline = false) {
  // Bound work before normalization; a Unicode scalar occupies at most two UTF-16 units.
  if (typeof value !== 'string' || value.length > max * 2) fail(field);
  let text = value.normalize('NFC');
  if (multiline) text = text.replace(/\r\n?/gu, '\n');
  if ((multiline ? TEXT_CONTROL : CONTROL).test(text) ||
      BIDI_OVERRIDE.test(text) || SURROGATE.test(text)) fail(field);
  text = text.trim();
  if ([...text].length > max) fail(field);
  return text;
}

function emailAddress(value) {
  const text = normalizedText(value, 'email', 254);
  const at = text.lastIndexOf('@');
  if (at < 1) fail('email');
  const local = text.slice(0, at);
  const suppliedDomain = text.slice(at + 1);
  if (local.length > 64 || !EMAIL_LOCAL.test(local) || local.startsWith('.') ||
      local.endsWith('.') || local.includes('..') ||
      /[\s/\\:%?#\[\]]/u.test(suppliedDomain)) fail('email');
  const domain = domainToASCII(suppliedDomain).toLowerCase();
  const labels = domain.split('.');
  if (domain.length > 253 || labels.length < 2 ||
      labels.some(label => !DOMAIN_LABEL.test(label))) fail('email');
  const result = `${local}@${domain}`;
  if (result.length > 254) fail('email');
  return result;
}

/** Validate the contact-form profile, not arbitrary identity documents or passwords. */
export function validateContactForm(input) {
  if (input === null || typeof input !== 'object' || Array.isArray(input)) fail();
  const prototype = Object.getPrototypeOf(input);
  if (prototype !== Object.prototype && prototype !== null) fail();
  const descriptors = Object.getOwnPropertyDescriptors(input);
  for (const key of Reflect.ownKeys(descriptors)) {
    if (typeof key !== 'string' || !FIELDS.has(key)) fail();
    if (!Object.hasOwn(descriptors[key], 'value') || !descriptors[key].enumerable) fail(key);
  }
  if (!Object.hasOwn(descriptors, 'fullName')) fail('fullName');
  if (!Object.hasOwn(descriptors, 'email')) fail('email');
  const fullName = normalizedText(descriptors.fullName.value, 'fullName', 100)
    .replace(/ +/gu, ' ');
  if (!NAME.test(fullName) || !/\p{L}/u.test(fullName)) fail('fullName');
  const email = emailAddress(descriptors.email.value);
  let phone = null;
  if (Object.hasOwn(descriptors, 'phone')) {
    phone = normalizedText(descriptors.phone.value, 'phone', 16);
    if (phone === '') phone = null;
    else if (!/^\+[1-9][0-9]{1,14}$/u.test(phone)) fail('phone');
  }
  let message = null;
  if (Object.hasOwn(descriptors, 'message')) {
    message = normalizedText(descriptors.message.value, 'message', 2000, true);
    if (message === '') message = null;
  }
  return Object.freeze({ fullName, email, phone, message });
}

/** The trusted caller owns schema creation, authorization, retention and database lifetime. */
export function createContactWriter(database) {
  const insert = database.prepare(
    'INSERT INTO contacts (full_name, email, phone, message) VALUES (?, ?, ?, ?)'
  );
  return input => {
    const contact = validateContactForm(input);
    return insert.run(contact.fullName, contact.email, contact.phone, contact.message);
  };
}
