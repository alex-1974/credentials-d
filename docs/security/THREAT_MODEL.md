# Threat Model and Security Contract

**Status:** Proposed for Issue #1  
**Date:** 2026-10-30

## 1. Purpose

`credentials-d` stores and retrieves small, high-value application
credentials such as OAuth access tokens and API keys.

The library is security-sensitive because possession of such a credential may
authorize actions against external systems. The library therefore treats
credentials as secrets rather than ordinary application preferences.

This document defines the security boundary that future public APIs and store
backends must satisfy.

## 2. Security objective

The primary objective is:

> Prevent credentials from being unnecessarily exposed, persisted in ordinary
> application state, confused across credential records, or returned when the
> selected backend cannot satisfy its declared security contract.

The library aims to make correct handling the normal path and accidental
exposure difficult.

It does not promise protection once the operating system or the process using
the secret is fully compromised.

## 3. Assets

The primary protected assets are:

- credential plaintext;
- vault decryption keys, if an encrypted-vault backend is admitted;
- backend-specific references that grant access to stored credentials;
- credential metadata where that metadata itself may disclose sensitive
  account or service information.

Opaque credential handles are not secrets by definition, but they must not
contain embedded credential plaintext.

## 4. Trust boundaries

### 4.1 Consumer application

The consumer is trusted to decide:

- which external identity a credential belongs to;
- which operation is authorized;
- when a credential should be stored, acquired, rotated, revoked or removed.

`credentials-d` does not make application authorization decisions.

### 4.2 credentials-d

The library is trusted to:

- keep persistent secret material behind a `CredentialStore` boundary;
- honor the declared semantics of the selected backend;
- minimize unnecessary plaintext lifetime and copying;
- reject malformed, unauthenticated or unsupported stored data;
- avoid secret disclosure through library-provided diagnostics and formatting.

### 4.3 Platform credential store

A platform backend relies on the operating system credential service and its
security boundary.

The library must not claim stronger isolation than the platform service
actually provides.

### 4.4 Encrypted vault

If admitted, an encrypted-vault backend relies on:

- the qualified cryptographic implementation;
- the secrecy of the derived or wrapped vault key while unlocked;
- authenticated vault-file integrity;
- the configured unlock mechanism.

The vault file itself is considered attacker-readable.

### 4.5 Operating system and process

The operating system kernel, root/administrator and code executing with full
control of the consumer process are outside the protection boundary.

## 5. Threat classes

### T1 — Accidental persistence

A consumer, backend or diagnostic path accidentally writes a credential to:

- settings;
- ordinary JSON/XML/SQLite configuration;
- logs;
- exception messages;
- crash metadata;
- temporary files;
- command-line arguments;
- clipboard content.

**Required response:** library APIs must avoid making these paths convenient,
and library-owned code must never intentionally emit credential plaintext to
them.

### T2 — Copied application files or backups

An attacker obtains normal application state, project files, configuration
files or backups.

**Required response:** those files must contain credential handles or encrypted
records, not credential plaintext.

A backend may document that its own platform-managed database or vault file is
part of the protected secret store.

### T3 — Malformed or tampered persistent data

An attacker can modify an encrypted vault file or other backend-controlled
persistent representation.

**Required response:** the backend must reject malformed, unsupported or
unauthenticated data and fail closed. It must not return partially decoded or
unverified secret bytes.

### T4 — Credential confusion

A consumer requests one credential and receives another because of identifier,
replacement, deletion, cache or backend-mapping errors.

**Required response:** credential identifiers and backend records must have
unambiguous mapping semantics. Replacement and deletion must not silently
retarget an existing handle unless the public contract explicitly defines that
behavior.

### T5 — Ordinary user on another OS account

Another non-privileged local user attempts to read credentials.

**Required response:** platform backends should rely on the operating system
credential boundary. File-vault backends must not depend on ordinary world- or
group-readable plaintext files.

Exact guarantees are platform-specific and must be documented.

### T6 — Another process under the same OS account

Another process running with the same user's privileges attempts to read stored
or in-memory credentials.

**Required response:** no backend-independent guarantee is made against an
arbitrary hostile same-account process.

A specific backend may provide additional isolation, but only if that property
is established and exposed by its backend contract.

### T7 — Another application profile under the same OS account

An application may present multiple human or logical profiles while all of them
run under one OS account.

**Required response:** `credentials-d` must keep records distinct and must not
confuse handles across profiles or consumers.

However, profile separation is not automatically a cryptographic security
boundary. Stronger isolation requires a backend that actually provides it, for
example an independently locked encrypted vault.

### T8 — Memory disclosure

An attacker obtains a process memory dump, attaches a debugger, injects code or
otherwise gains read access to the running process while a credential is in
use.

**Required response:** minimize plaintext lifetime and copies, but no claim is
made that `credentials-d` can keep an actively used secret confidential from
an attacker controlling the process.

### T9 — Root/administrator or compromised operating system

The attacker controls the OS, kernel, administrator account or equivalent
trusted platform component.

**Required response:** out of scope. The library must not document claims that
imply protection against this attacker.

### T10 — Malicious code in the same process

A native plugin, injected library or other hostile code executes in the same
address space as the consumer.

**Required response:** out of scope for confidentiality of secrets while
available to the process. API visibility is not a sandbox.

## 6. Backend-independent security invariants

The following invariants apply to every production backend unless a stronger
backend-specific rule is documented.

### S1 — Secrets are not preferences

Credential plaintext must never be represented as ordinary application
preferences by this library.

### S2 — Handles contain no credential plaintext

A `CredentialHandle` or equivalent identifier must be safe to persist in
ordinary application settings.

### S3 — Persistence crosses CredentialStore only

Persistent credential operations occur only through a `CredentialStore`
backend.

The semantic core must not provide helper APIs that silently serialize secrets
into general-purpose application storage.

### S4 — No intentional secret logging or formatting

Library-owned:

- log messages;
- exception text;
- error strings;
- `toString`/formatting support;
- debug summaries;

must not contain credential plaintext.

Where the D type system can reject accidental formatting or implicit string
conversion, the public API should use that enforcement.

### S5 — Explicit plaintext acquisition

Plaintext must become available only through an explicit secret-acquisition
operation.

Metadata lookup must not implicitly acquire the credential.

### S6 — Plaintext lifetime is minimized

The implementation must avoid unnecessary copies and retain plaintext only for
the operation or ownership lifetime required by the public contract.

This is a minimization guarantee, not a claim of perfect memory secrecy.

### S7 — Fail closed

A production backend must not return credential plaintext when:

- stored data fails authentication or integrity verification;
- the format version is unsupported;
- the backend is locked;
- a required backend capability is unavailable;
- a persistent operation completed only partially where correctness cannot be
  established.

### S8 — Backend properties are not invented

The common API must not claim:

- hardware-backed storage;
- user-presence enforcement;
- per-profile cryptographic separation;
- secure deletion;
- session locking;

unless the selected backend actually provides the claimed property.

Material differences must be represented through capabilities or documented
backend contracts.

### S9 — Secret and metadata are distinct

Non-secret metadata should be accessible without acquiring secret bytes where
possible.

Metadata fields that may themselves be sensitive must be identified explicitly.

### S10 — Rotation and replacement do not expose the old secret

Replacing or rotating a credential must not return the old credential as an
incidental result.

The API may expose lifecycle status but not old plaintext.

### S11 — Security-sensitive errors are non-revealing

Errors may identify:

- backend;
- operation;
- locked/not-found/corrupt/unsupported status;
- relevant non-secret identifiers;

but must not include secret contents.

## 7. Meaning of "locked"

`locked` is a semantic state in which acquisition of secret plaintext is not
permitted.

The exact mechanism is backend-specific.

### 7.1 Platform credential store

For a platform store, locked means that the underlying credential service
refuses secret retrieval because of its platform/session/store policy.

`credentials-d` must not synthesize a stronger security meaning than the
platform provides.

### 7.2 Encrypted vault

For an encrypted vault, locked means at minimum:

- no usable vault decryption key is retained by the vault backend;
- encrypted credential records may remain persisted;
- acquiring credential plaintext fails until successful unlock.

Whether metadata remains readable while locked is a format/API decision and
must be documented.

### 7.3 Memory/test stores

A memory or mock backend may report that lock semantics are unsupported.

Such a backend must not be presented as equivalent to a persistent production
credential store.

## 8. Plaintext memory contract

Credential plaintext may exist only where required for:

- caller input during store/replace;
- backend transfer;
- explicit acquisition by the consumer;
- cryptographic processing for an encrypted vault.

The implementation should:

- prefer byte-oriented secret types over GC-managed `string`;
- minimize copying;
- avoid hidden formatting conversions;
- erase owned mutable buffers before release where technically meaningful;
- document when external APIs or runtimes may create unavoidable copies.

The library does not guarantee that compiler optimizations, foreign libraries,
the OS, swap, core dumps or a compromised process cannot retain or observe a
copy.

Any claimed deterministic zeroization behavior must be independently verified
for the exact D/compiler/backend implementation before it becomes a public
guarantee.

## 9. Logging, diagnostics and crash handling

Credential plaintext must not be intentionally emitted by library code into:

- logs;
- traces;
- metrics labels;
- exception messages;
- assertion messages;
- crash-report annotations;
- test failure output;
- Ddoc examples.

Tests must use synthetic credentials and must not depend on real account
tokens.

A future debug mode does not weaken this rule.

## 10. Deletion semantics

Deletion is backend-specific and must be described precisely.

### 10.1 Memory owned by credentials-d

Owned mutable plaintext buffers should be erased before release where the
implementation can make a meaningful and testable guarantee.

This does not imply that every historical copy in the process has been erased.

### 10.2 Platform credential store

`remove` requests deletion from the platform store and reports the resulting
backend status.

The library does not claim physical erasure from:

- filesystem history;
- platform backups;
- snapshots;
- forensic storage;
- external synchronization systems;

unless the platform contract explicitly provides that guarantee.

### 10.3 Encrypted vault

Removing a record must make it absent from the current logical vault state.

A rewritten vault must not intentionally retain the removed plaintext.

The library cannot generally guarantee erasure of previous encrypted file
versions from filesystem snapshots, copy-on-write storage or backups.

### 10.4 Compromise response

Deletion is not a substitute for credential revocation or rotation after
suspected disclosure.

Applications using revocable external credentials should provide their own
revocation/re-authorization workflow.

## 11. Backup semantics

Ordinary application backups must not acquire credential plaintext through
`credentials-d`.

For platform credential stores, backup behavior belongs to the platform.

For encrypted vaults, a copied vault file is assumed attacker-readable and must
remain confidential and integrity-protected without relying on file secrecy.

## 12. Capability reporting

The API should be able to represent material backend properties without
promising a lowest-common-denominator fiction.

Candidate capabilities to qualify in Issue #2/#3 include:

- persistent storage;
- lock/unlock support;
- independent application-controlled unlock;
- user-presence support;
- hardware-backed protection;
- native OS credential service;
- deletion confirmation semantics.

Capability names are not frozen by this document.

## 13. Explicit non-goals

`credentials-d` does not provide or claim:

- OAuth authorization flows;
- identity verification for an external service;
- application authorization policy;
- account/profile access control;
- password-manager functionality;
- protection against root/administrator;
- protection against a fully compromised OS;
- confidentiality from hostile code in the same process while a secret is
  available;
- universal protection from arbitrary same-OS-account processes;
- guaranteed physical secure deletion from storage media;
- a general cryptographic API;
- custom cryptographic primitives.

## 14. Required regression protection

Future implementations must derive tests from the security contract.

At minimum, the test plan must include:

| Contract | Required regression protection |
| --- | --- |
| S1/S3 | external consumer test proving persistent APIs require a store abstraction |
| S2 | handle round-trip tests proving handles contain only non-secret identity/reference data |
| S4/S11 | formatting, error and exception tests using sentinel secret bytes and checking they never appear in produced text |
| S5 | API tests proving metadata lookup does not acquire secret bytes |
| S6 | lifecycle tests for owned secret buffers; negative compile tests where D can prevent copying/conversion |
| S7 | locked/corrupt/unsupported-format/partial-write tests for each applicable backend |
| S8 | capability contract tests per backend |
| S9 | metadata-only access tests |
| S10 | replacement/rotation tests proving old plaintext is not returned |
| deletion | backend-specific deletion tests, without claiming physical erasure beyond the backend contract |
| vault integrity | modified, truncated, malformed and unauthenticated file corpus plus fuzzing if a vault is admitted |
| platform stores | real-platform integration tests in addition to mocks |

Tests involving secret leakage should use distinctive synthetic sentinel values
and check all library-owned textual outputs reachable from the tested path.

## 15. Review rule for future changes

A proposed API or backend change is not acceptable merely because it works.

Security-sensitive changes must answer:

1. Which asset does this operation expose or persist?
2. Which trust boundary does it cross?
3. Which invariants above apply?
4. What new failure state exists?
5. Does the operation fail closed?
6. Which regression test proves the intended property?
7. Does the change claim a backend property that is not actually guaranteed?

If those questions cannot be answered, the security contract is not yet
sufficiently specified for the change.

## 16. References

The following external guidance informs this threat model:

- OWASP Cheat Sheet Series, *Secrets Management Cheat Sheet* — secret
  lifecycle, least privilege, rotation/revocation and the rule that plaintext
  secrets must not be logged:
  https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html
- RFC 9700, *Best Current Practice for OAuth 2.0 Security* — access tokens are
  sensitive secrets and stolen bearer tokens are replayable unless separately
  constrained:
  https://www.rfc-editor.org/rfc/rfc9700.html
- RFC 8252, *OAuth 2.0 for Native Apps* — native applications are public
  clients and must not rely on an embedded client secret being confidential:
  https://www.rfc-editor.org/rfc/rfc8252.html

These references provide security context. They do not expand
`credentials-d` into an OAuth library.
