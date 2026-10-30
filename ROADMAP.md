# credentials-d Roadmap

## Status

`credentials-d` is in pre-0.1 architecture qualification.

The first consumer is expected to be Dunia, but the library is deliberately
protocol- and application-independent.

## M0 — Repository and security baseline

- establish repository, package and module identity;
- establish `main` / `develop` workflow and compiler baseline;
- define threat model and security boundary;
- define responsible security-reporting policy;
- establish a dependency/update policy for security-sensitive native code.

## M1 — Semantic core

Qualify a small public model for:

- `CredentialId` / opaque credential handles;
- secret ownership and lifetime;
- explicit acquisition and release;
- deletion semantics;
- capability discovery;
- failure behaviour.

The API must not require secrets to become ordinary GC-managed strings.

## M2 — Testable store contract

Implement:

- ephemeral in-memory store;
- deterministic mock/test store;
- contract tests shared by all store backends;
- negative API tests for accidental formatting/logging/copying where D can
  enforce the restriction.

No platform keyring or encrypted-vault backend is required for M2.

## M3 — Platform credential stores

Research and qualify independently:

- Linux Secret Service;
- Windows Credential Manager;
- macOS Keychain.

Platform backends must preserve one common semantic contract while exposing
material capability differences rather than hiding them.

## M4 — Encrypted vault backend

Only after the store contract is stable:

- decide whether an application-controlled encrypted vault is justified;
- qualify the cryptographic backend independently;
- define a versioned authenticated file format;
- require corruption/tamper detection;
- qualify password KDF parameters;
- qualify atomic persistence, locking, migration and crash behaviour;
- add fuzzing and malformed-input corpora.

No custom cryptographic primitive is in scope.

## M4.1 — Hardware-assisted vault unlock

Qualify optional external vault-key protectors without changing the native
CredentialStore contract:

- generic authenticated vault-key envelopes;
- multiple independent wrappers for one random vault key;
- FIDO2 / CTAP hmac-secret through a narrow libfido2 FFI;
- explicit user-presence versus user-verification policy;
- no silent downgrade when UV / credProtect cannot be satisfied;
- transient SecretBuffer-based PIN handling;
- no device-path persistence;
- no application credential storage on the authenticator;
- deterministic/no-hardware CI plus a separate physical-authenticator
  production qualification.

The existing passphrase wrapper remains a recovery path for vault format v1.

## M5 — First public release

Release only after:

- DMD and LDC gates pass;
- platform backends used by the release are qualified on their native OS;
- security documentation matches implementation;
- external consumer tests pass;
- package archive and public Ddoc are reviewed;
- no unresolved release-blocking security issue remains.
