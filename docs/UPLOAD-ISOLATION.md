# Isolate uploads from approved application storage

An uploaded file is untrusted input even if its name and extension look normal. Keep newly received bytes in a quarantine area that the public application cannot use as approved content. Scanning and release into trusted storage are separate operations under different identities.

This guide and [uploads.compose.yaml](../infra/container/uploads.compose.yaml) define a storage/network topology. They do not supply an HTTP upload server, antivirus adapter, durable approval service or download application. Supply those reviewed role-specific images and implement the contracts below before deployment. The existing dependency-quarantine tool is for inspecting build artifacts; it is not a web upload endpoint.

## Separate the roles and storage

| Role | Storage access | Network access in the template | Required behavior |
| --- | --- | --- | --- |
| Intake | Read/write quarantine only | Internal upload-ingress network; no host-published ports | Authorize uploads, enforce quotas, generate object IDs and write bounded temporary objects. Cannot mount approved storage or verdict storage. |
| Scanner | Read-only quarantine; read/write verdicts | None | Inspect an exact stable byte sequence under resource limits; never execute it. Write a bounded structured verdict tied to that object and hash. |
| Promoter | Read-only quarantine and verdicts; read/write approved storage | None | Validate verdict and policy, copy to a private candidate, verify copied bytes, then publish atomically. It is the only normal writer to approved storage. |
| Media/download service | Read-only approved storage | Separate internal media-ingress network; no host-published ports | Authorize each read and serve approved bytes without interpreting them as code. |
| Main application | No upload-volume mount supplied by this topology | Its own existing network | Refer to approved objects by server-generated ID and ownership metadata, not user paths. |

The Compose template uses three distinct project-scoped volumes: `quarantine`, `verdicts` and `clean`. It does not accept external aliases that accidentally point all three at the same volume. Mounts use `nocopy` so image contents are not silently copied into a new data volume. Filesystem directories inside one shared mount are not the same isolation boundary as separate mounts and identities. For stronger isolation, put upload processing on a separate host or storage account with an independently enforced access policy.

Do not attach the main application, reverse proxy or intake container to every volume/network for convenience. Keep primary database credentials, backups and secret-store mounts out of the intake/scanner roles. Expose only the intended intake and media endpoints through an authenticated, explicitly configured ingress. An internal Docker network does not implement per-HTTP-user authorization. This template publishes no ports; the actual reverse-proxy routing remains a separate integration.

## Provision the role identities deliberately

The one-shot `prepare` profile requires a reviewed Python image supplied by repository and digest. It checks that all three volumes are empty, then assigns directory mode `0750` and owners/groups:

- quarantine: UID `10001`, GID `20001`;
- verdicts: UID `10002`, GID `20002`;
- clean: UID `10003`, GID `20003`.

The scanner receives supplementary group `20001`; the promoter receives `20001` and `20002`; the media service receives `20003`. Applications must create data files with mode `0640` and preserve the corresponding primary group, and create needed child directories with appropriately restrictive traversal rights. Do not solve a permission error with `0777` or by running all roles as root. Adapt IDs to the target host/image policy with the entire access matrix reviewed together.

Use a new dedicated Compose project and new volumes. Supply the four reviewed role-image repositories/digests and the Python image through public metadata only; secrets use a separate trusted mechanism. Run only the `prepare` profile first, inspect the resulting ownership, then start the explicitly selected runtime roles. Do not use an unrestricted `up` with all profiles or run preparation over existing production content. Do not merge this file into another Compose project without reviewing the resulting mounts, networks and names.

The runtime roles have non-root identities, read-only root filesystems, dropped capabilities, no-new-privileges, bounded resources and no Docker socket or host bind mounts. Scanner and promoter have no network. Signature/database updates for scanning need a separate controlled path, such as a newly verified scanner image with current data; do not silently give the scanner internet access or mount host administration sockets.

Named-volume data mounts here do not themselves request `noexec`. Use a suitable storage-driver/host mount policy where supported and verify it on the actual host; file permissions and “no shell” are not guarantees that an interpreter cannot process bytes. The essential rule remains: never execute uploaded content. A malicious parser can require a stronger isolated sandbox than an ordinary container.

## Intake contract

Authorize the uploading principal and target purpose before accepting bytes. Enforce per-request, per-user and global limits: uploaded bytes, simultaneous uploads, temporary space, object count and timeouts. The proxy's body limit and streaming handler's byte count must agree. Reject unsupported content types; the client filename, extension and MIME declaration are hints, not proof of file format.

Generate a cryptographically unpredictable server-side object ID. Preserve an original filename only as untrusted display metadata, not as a path. Never use absolute paths, `..`, symlinks, hard links or extracted archive names to select the destination. A client must not choose an approved-store key or another user's object ID.

Write into a private temporary object using exclusive creation. Count bytes while receiving them, complete the write, record size and SHA-256, and close it before making a pending object discoverable. Use a durable state transition so a partial write or process crash cannot create an approved object. Prevent concurrent modification after handoff using a supported immutable object version, ownership transfer, stable snapshot or equivalent enforceable mechanism.

## Scan-to-promotion contract

A read-only scanner mount does **not** make the bytes immutable while intake retains write access to the same volume. Reading a filename twice can produce two different objects. A hash observed before scanning is insufficient if the scanned and published bytes differ.

The scanner must inspect the exact bytes whose digest it records. Use a stable snapshot or create a private bounded copy that intake cannot modify. Bind its verdict to object ID, immutable version, size, digest, scan engine/database versions, policy version, completion time, coverage and result. An uploader cannot write verdicts or supply an `approved=true` substitute. The promoter trusts only the designated scanner/approval service and still checks authorization and freshness.

For archives, inspect supported metadata before extraction: declared uncompressed size, member count, nesting, paths, links and other limits. Reject unsupported or indeterminate cases under the application's policy, and also count actual expanded bytes during bounded extraction. Do not trust archive metadata to enforce runtime limits. Store extracted candidates under generated identifiers and do not preserve attacker-selected paths. Antivirus scanning does not replace these checks.

The promoter copies the approved candidate into a newly created temporary file in approved storage without exposing it through downloads. It computes the digest of the copied bytes and requires it to match the exact reviewed verdict. Only after all checks and required durable writes does it publish the object and its approval record atomically using a no-overwrite operation or the storage provider's conditional commit/version primitives.

Never make the object downloadable and validate it afterward. If the source is changed while copying, the final digest must fail approval unless the copied bytes are exactly the approved content. If the storage/verdict state is lost, inconsistent or incomplete, keep the object unavailable and reconcile the recorded operation. Retries must not overwrite another object or duplicate an external effect.

## Approved does not mean executable or public

Keep approved storage outside the web root and application code directories. Serve through a handler that checks ownership and current read permission. An antivirus result is not a grant to every visitor. Use a separate media origin where appropriate, restrictive response headers, an intentional content type and download disposition. Do not interpret uploaded PHP, scripts, templates or executable formats as server code.

Untrusted HTML/SVG and other active document formats can execute in a browser even though the server never executes them. Apply a strict format policy, safe conversion/sanitization when appropriate, download-only behavior and a separated origin according to the product's needs. Do not render arbitrary uploads under the authenticated application origin with its cookies. Retain the [safe input/output rules](WEB-INPUT-PROTECTION.md) and [sensitive-cache bypasses](CLOUDFLARE-EDGE.md).

Logs and records should contain only necessary metadata. Keep PII and confidential uploaded content out of public reports. Define retention, abandoned-upload cleanup and deletion authorization. Deleting quarantine or approved objects is a separate controlled operation; never clean a whole shared volume to remove one rejected upload.

## Verification before adoption

The kit's Compose tests verify normalized mount/network boundaries and reject missing image settings. A separate synthetic Linux test also exercised the exact preparation code and role UID/GID read/write permissions; see [VALIDATION.md](VALIDATION.md). These tests do not prove that supplied application images implement upload, scanning, promotion or authorization correctly. The runtime test used no networking and therefore does not establish the template's ingress behavior.

On the target environment, verify:

- intake cannot mount/read/write approved storage or verdicts;
- scanner cannot change quarantine/approved storage and cannot contact the network;
- promoter accepts only fresh matching structured verdicts and never executes content;
- media cannot write approved storage and cannot serve pending objects;
- denied/oversized uploads, unsupported formats, archive traversal/links/bombs and quota exhaustion fail safely;
- replacing bytes during scan/copy, concurrent promotion, restarts and lost verdict state cannot publish an unapproved object;
- an unauthorized download, cache leak or direct origin path cannot expose another user's file;
- cleanup removes only the intended object and preserves the application's primary storage and backups.

Use synthetic harmless fixtures in a dedicated environment. No malicious specimen or live upload service is included by this guide. See [SECURITY.md](../SECURITY.md) for the explicit standards mapping and [service protection](SERVICE-PROTECTION.md) for ClamAV integration limits.
