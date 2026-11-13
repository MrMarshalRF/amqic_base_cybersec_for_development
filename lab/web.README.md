# Runnable synthetic web lab

Node.js 22.14+ with `--experimental-sqlite` runs this standard-library-only HTTP lab. It listens only on `127.0.0.1`; other bind addresses are rejected. Use an isolated, private data directory. Never enter real credentials or personal data. The page is a plain native form fixture, not a production UI or complete authentication deployment.

```sh
node --experimental-sqlite lab/web-app.mjs --data /private/synthetic-web-lab --clamd-host 127.0.0.1 --clamd-port 3310 --port 0
```

The command prints its actual loopback URL and PID after binding. The configured local `clamd` must already be running; this lab does not launch it. Startup checks the actual scanner with an empty probe and fails if configuration is missing or scanning is unavailable. No permissive scanner fallback is provided. Stop the process with Ctrl+C. Use [the upload lab guide](upload-pipeline.README.md) for scanner boundaries.

Open the printed URL. The page displays two explicitly synthetic accounts, their current TOTP codes and the synthetic CAPTCHA answer. Complete **login → password → CAPTCHA → TOTP** in order. The same server core enforces each stage, single-use tickets, source binding, current scopes, session revocation and TOTP replay prevention. These public seeds/passwords and the simulated CAPTCHA are teaching fixtures, not real factors. Authentication state is in memory and resets on restart; contacts and upload storage persist in the chosen directory. Do not reuse that directory between unrelated exercises.

The page offers a contact form and owner-scoped upload flow. SQL parameters store even hostile SQL/HTML-looking message text as data. Result rendering uses `textContent`. Uploads first remain pending and inaccessible, then an explicit owner request scans them. Only clean, hash-matching bytes become downloadable by that owner. Downloads are attachments with `application/octet-stream` and `nosniff`; antivirus clearance does not establish that arbitrary content is safe to execute or render.

## HTTP contract

`GET /api/bootstrap` establishes an HttpOnly `SameSite=Strict` browser cookie and returns a CSRF token plus public synthetic fixture hints. Every POST requires the exact loopback `Origin`, this cookie and `X-CSRF-Token`. Login stages accept JSON `{value}` then `{ticket,value}` at `/api/login`, `/api/password`, `/api/captcha`, `/api/totp`. Successful TOTP sets an independent HttpOnly session cookie; no raw session is returned to JavaScript. `/api/logout` accepts `{}`.

`GET/POST /api/contacts` lists or creates only the current owner's contacts. The contact JSON has required `fullName,email` and optional `phone,message`. Submitted `ownerId,userId` claims are ignored. `POST /api/uploads` accepts raw `application/octet-stream` up to 1 MiB; a client filename or owner header is never used as a storage path or identity. `POST /api/uploads/:id/process` accepts `{}` and requests scanning; `GET /api/uploads/:id` downloads accepted bytes. Foreign owners receive no object contents.

Requests have strict methods, routes, schemas and content types; bounded streaming bodies, header/time limits and per-source quotas; exact Host/Origin checks; same-origin CSRF; no CORS wildcard; restrictive CSP and other headers on success/errors. This HTTP loopback exception omits `Secure` cookies because the lab uses HTTP. Real deployment requires HTTPS, Secure cookies, real CAPTCHA/enrollment/protected-factor adapters, coordinated multi-instance state, operational retention/backups, load handling and independent integration validation.

## Verification

```sh
node --experimental-sqlite --test lab/web-app.test.mjs
```

The tests use actual loopback HTTP requests against temporary task-owned listeners and explicitly synthetic scanner verdicts. They exercise successful complete login and logout, bypass/replay/source attacks, CSRF and origin/Host rejection, malicious direct requests bypassing browser validators, SQL parameter binding, cross-owner denial, pending/rejected uploads, content/header/schema limits, chunked limits, revocation during a streamed request and unsafe-bind rejection. Each listener is stopped and its absence checked; temporary test data is removed. Synthetic scanner tests are not evidence of a real antivirus run or production security. Run the separate ClamAV integration checks for that evidence.

For embedding, `createLabApp({dataRoot,clamdHost,clamdPort})` returns `{start,close,core,fixture}`. `start({host:'127.0.0.1',port:0})` returns the observed URL/port. Always await `close()`; it closes owned sockets, waits for handlers and closes SQLite. Tests may explicitly inject `scanner` and `clock`; this is not a CLI feature and does not disable any login stage.
