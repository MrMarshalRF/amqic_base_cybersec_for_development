# Protecting personal-data fields on websites

## Keep data separate from instructions

The fundamental defense is to prevent form values from becoming executable instructions. Keep SQL statement structure fixed and bind values as parameters. Do not invoke a shell to process a form. Render plain text with safe DOM operations instead of parsing it as HTML. Validate each field on the server for its intended purpose, but do not rely on a list of attack words.

A word such as `SELECT` can be legitimate text. A SQL-looking message stored with a parameterized query remains data. Rejecting that word while later concatenating an unrecognized string into SQL leaves the actual vulnerability present. Similarly, removing `<script>` does not establish safe HTML, and escaping SQL does not make a shell command safe.

This kit provides [pii-input.mjs](../reference/pii-input.mjs): a small server-side contact-form profile and a fixed parameterized SQLite insert. It is not a complete website, a general personal-name standard, HTML sanitizer, identity verifier, encrypted database or compliance assessment. Its [tests](../reference/pii-input.test.mjs) exercise actual SQL storage with attack-like text and validation failures.

## How this connects to container protection

The field is displayed in the visitor's browser. The submitted request reaches a server handler, which can run inside the constrained application container described in [INFRASTRUCTURE.md](INFRASTRUCTURE.md). The browser, server process and database remain separate trust boundaries:

1. **Browser to ingress:** the visitor controls the submitted bytes. HTTPS protects transport; request/body limits and the route policy bound what reaches the handler. Client validation is only a usability aid.
2. **Ingress to application container:** an allowed route invokes existing application code. The external request must not select an arbitrary executable, shell command, template, module or tool. The server validates the schema and performs authorization before using the accepted fields.
3. **Application to database or another service:** use a fixed operation with bound data and a least-privilege service identity. Keep databases and administrative interfaces on the intended private network; no Docker socket or runtime-management endpoint belongs in the public application container.
4. **Stored data back to browser:** render as plain text or use context-appropriate escaping. The value remains untrusted data after database storage, queue transport or a successful scan.

The container's non-root identity, read-only code filesystem, dropped capabilities, syscall/resource limits and restricted network access reduce the consequences of a compromised process. A minimal runtime without shells or system utilities removes some tools an attacker might use. These controls do not guarantee that a process cannot execute code or access its own memory: the application necessarily runs code, and an interpreter or runtime may expose dangerous APIs even without `/bin/sh`.

Use both layers together. Input values never enter `eval`, a shell or dynamic SQL; the container also lacks unnecessary privileges, tools, host mounts and network access. Container isolation does not repair a concatenated SQL query, and parameterized SQL does not prevent an overprivileged container from accessing the host if another vulnerability is exploited. See [service protection](SERVICE-PROTECTION.md) for rate/admission controls; solving a request puzzle does not make the resulting input trusted.

## Choose a schema for the actual form

The example accepts only these own enumerable JSON properties; unknown fields are rejected rather than assigned to a database object:

| Field | Profile | Boundary |
| --- | --- | --- |
| `fullName` | Required string; NFC; trim/collapse ASCII spaces; at most 100 Unicode code points; letters/marks separated by spaces, periods, apostrophes or hyphens | A limited contact-name profile, not proof of identity. Some legitimate names/scripts need a reviewed extension. |
| `email` | Required; at most 254 characters after canonical domain conversion; conservative unquoted ASCII local part; IDNA ASCII domain; preserve local-part case | Quoted local parts, domain literals and internationalized local parts are unsupported. DNS/deliverability/ownership are not verified. |
| `phone` | Optional; omitted or blank becomes null; otherwise `+` followed by 2–15 digits with a nonzero first digit | Canonical international-format input only. This does not verify allocation, country-specific rules or ownership. |
| `message` | Optional plain text; omitted or blank becomes null; NFC, trimmed, CRLF/CR to LF; at most 2,000 Unicode code points | No HTML interpretation. Attack-looking text is retained as data. This is not an upload or rich-text field. |

The validator bounds string length before normalization. It rejects C0/C1 controls in single-line fields, disallowed controls in messages, lone UTF-16 surrogates and bidi override/isolate controls. Its narrow name grammar also excludes some format characters used in legitimate scripts. Provide a product-specific supported alternative rather than instructing a person to falsify their name. Never apply these normalization rules to passwords, signatures, tokens or arbitrary binary input.

Require strings instead of coercing arrays, objects or numbers. Reject fields such as `isAdmin`, `ownerId`, `role` and `__proto__`; obtain privileged attributes from authenticated server state. Treat phone/email verification as separate workflows with expiry, attempt limits and appropriate privacy controls.

## Validate on the server, even when the browser checks

Browser `required`, `maxlength`, input types and helpful messages improve usability. An attacker can send requests without the form, so browser checks never establish trust. HTML `maxlength` uses UTF-16 units; the module's final character counts use Unicode code points. Keep client/server limits compatible and test multilingual inputs.

At the HTTP boundary, before calling the module:

1. Restrict the route and method. For this example, accept one JSON object with the expected content type; uploads and URL-encoded forms need their own bounded parsers.
2. Bound raw request bytes, decompressed bytes if supported, parsing depth, time and concurrent requests. A suitable starting body limit for this small profile is 16 KiB; adapt it to the complete protocol. Field limits do not stop an oversized body before parsing. Bound duplicate/nested input handling in the parser and reject ambiguous encodings.
3. Apply CSRF protection for cookie-authenticated state changes, the application's origin policy, authentication/authorization where required, and rate limits. CORS alone is not authorization or CSRF protection. Public contact forms still need abuse limits and resource quotas.
4. Parse once, validate once, and pass only the returned fields to a fixed handler. Do not merge the original request object back into the accepted record.
5. Return a generic validation failure, with only fixed field names if needed. Do not include submitted PII, database errors, stack traces or scanner matches in the response or ordinary logs.

The helper expects ordinary parsed JSON data, not hostile JavaScript proxies or objects from untrusted plugins. It rejects accessor/non-enumerable/symbol fields without invoking getters, but it is not a JavaScript sandbox. It also does not implement the HTTP/body/CSRF layer above.

## Fixed SQL and an actual storage example

`createContactWriter(database)` prepares this statement once:

```sql
INSERT INTO contacts (full_name, email, phone, message) VALUES (?, ?, ?, ?)
```

All four values go through the SQLite binding API. None becomes a table name, column name, operator or SQL fragment. A caller owns the connection and creates the appropriate schema during a reviewed migration, for example in a synthetic in-memory demonstration:

```js
import { DatabaseSync } from 'node:sqlite';
import { createContactWriter } from './reference/pii-input.mjs';

const db = new DatabaseSync(':memory:');
try {
  db.exec(`CREATE TABLE contacts (
    id INTEGER PRIMARY KEY,
    full_name TEXT NOT NULL,
    email TEXT NOT NULL,
    phone TEXT,
    message TEXT
  )`);
  const save = createContactWriter(db);
  save({
    fullName: 'Example Person',
    email: 'example@example.test',
    message: "'); DROP TABLE contacts;--"
  });
} finally {
  db.close();
}
```

This intentionally stores the SQL-looking message as text; it does not execute it. Do not replace binding with template interpolation, concatenate a `WHERE` clause, or accept arbitrary database identifiers from the form. If a feature needs a dynamic sort/column, map a small server-defined option to a fixed identifier. Use the target database driver's real parameter API; placeholder syntax differs by driver.

For production storage, enforce database least privilege, ownership and retention, authenticated reads/updates, protected backups, encryption where required and a tested deletion workflow. The demo database is not an encrypted personal-data store. A validated email or name does not authorize viewing another person's record.

## Plain-text browser output

When showing a stored message, use a trusted application-created element:

```js
const messageNode = document.createElement('p');
messageNode.textContent = acceptedRecord.message ?? '';
messagesContainer.append(messageNode);
```

Do not put form values into `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write`, event-handler attributes, `eval`, or string-based timer handlers. A CSP is additional protection, not a reason to parse arbitrary form values as markup. The fact that data came from your database does not make it safe HTML: stored XSS begins with stored data being interpreted unsafely later.

For server-rendered templates, retain automatic context-appropriate escaping. HTML text, attributes, URLs, JavaScript and CSS are different contexts; a generic escape function does not make every use safe. Rich text requires a maintained allowlist sanitizer and a separate format contract. It is intentionally not supported by this plain-text module.

## No shell or secondary interpretation

The module contains no shell/process invocation. Keep that invariant in the handler and downstream jobs. Never construct a command line from a name, phone, email or message. If an unrelated feature must invoke a fixed executable, review its argument semantics and isolate it; using an argument array prevents shell parsing but does not stop the called program from interpreting attacker-controlled options or expressions.

Do not use form values as a filesystem path, template name, URL to fetch, log format string, regular-expression source, mail header or spreadsheet formula without a separate destination-specific design. For example, newline rejection helps single-line fields, but email must still be sent through a structured mail API; its HTML body requires safe rendering and its destination must satisfy authorization. Use server-generated object IDs and [isolated quarantine/approved storage](UPLOAD-ISOLATION.md) for uploads, with an exact-byte promotion check before publication. Do not mutate the input until it happens to pass a scanner.

## Regression checks and adoption

Run from the kit root with the supported Node runtime:

```sh
node --experimental-sqlite --test reference/pii-input.test.mjs
```

The tests include non-Latin names, canonical domains, valid address punctuation, forbidden types/properties, getters, length/control limits, sensitive-error handling and a real parameterized SQLite insert containing SQL, shell and HTML-looking strings. No shell is invoked. These tests do not run a browser, start an HTTP server or prove that a consuming website uses safe sinks.

For your actual website, test direct HTTP requests that bypass browser checks, oversized/malformed bodies, CSRF, authorization, rate limits, and stored text rendered in every view/email/export. Verify no downstream task interprets the value as instructions. Maintain test data without real PII and ensure operational logs do not capture submitted fields by default.

## References and scope

- [OWASP Input Validation](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html): field-specific syntactic/semantic validation and server enforcement.
- [OWASP SQL Injection Prevention](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html): parameterization and limited identifiers.
- [OWASP OS Command Injection Defense](https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html): avoiding command execution and defending argument boundaries.
- [OWASP DOM XSS Prevention](https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html) and [XSS Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html): safe DOM sinks and context-aware output handling.
- [Node.js SQLite](https://nodejs.org/docs/latest-v22.x/api/sqlite.html): prepared statements and value binding for this example.

These are design references, not claims of certification or complete protection of an integrated website. The module is a reusable starting point; the application owns its transport, storage, rendering, privacy and deployment controls.
