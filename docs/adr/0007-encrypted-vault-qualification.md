# ADR 0007 — Encrypted vault cryptographic backend and format qualification

**Status:** Accepted for Issue #4  
**Date:** 2026-10-30  
**Decision:** ADOPT libsodium through a narrow private FFI for an optional vault backend

## Context

credentials-d already prefers native operating-system credential stores.

An application-controlled encrypted vault is still useful when a consumer needs
an explicit protection boundary independent of the current OS credential store,
for example when several logical users share one OS account or when a portable
application-specific credential store is deliberately required.

The vault is an optional backend. It is never an automatic fallback.

The cryptographic dependency must expose only the small primitive set required
by the vault and must have a clear security-update path.

## Decision

Use the official libsodium implementation through a narrow private D FFI.

Do not use the historical broad D libsodium wrapper as the security boundary,
and do not expose a general-purpose crypto API from credentials-d.

The selected primitive set is deliberately small:

- `sodium_init` and runtime-version qualification;
- `randombytes_buf`;
- `crypto_pwhash` with Argon2id;
- XChaCha20-Poly1305-IETF authenticated encryption;
- `sodium_memzero`;
- secure-memory helpers only if separately justified.

Native OS credential stores remain the default recommendation.

## Candidate comparison

### D Botan port

Botan-D provides a broad pure-D cryptographic implementation and tracks Botan
3.x, but it is a separate D translation rather than a thin binding to the
official C++ implementation. Security fixes therefore require independent
porting and verification. Its reachable surface is also far larger than this
vault requires.

**Decision:** not selected for the first vault backend.

### Official Botan through a bridge

This would use the official implementation, but a dedicated bridge plus the
large native dependency is unnecessary for the narrow required primitive set.

**Decision:** not selected for the first vault backend.

### Existing general D libsodium binding

The historical `carblue/sodium` binding documents libsodium 1.0.18 and warns
that binding/runtime mismatch can lead to undefined behavior.

**Decision:** do not make it the vault security boundary.

### Narrow official libsodium FFI

libsodium provides the exact required high-level primitives through a stable C
ABI and a deliberately misuse-resistant API.

**Decision:** selected.

## Initialization and runtime policy

`sodium_init()` must succeed before any other libsodium primitive is used.
Failure makes the backend unavailable.

The FFI must validate the runtime capabilities/version needed by the declared
ABI instead of assuming that successful dynamic linking proves compatibility.

Production packaging should use a currently supported, security-maintained
libsodium build. Distro backports may remain valid even when the upstream point
release number is older; qualification is therefore based on required ABI
surface plus supported security-update provenance, not only a raw version
string.

Dependency updates are security-relevant release work.

## Key hierarchy

```text
passphrase
    │
    ▼
Argon2id
    │
    ▼
KEK
    │
    ▼
authenticated unwrap
    │
random 256-bit vault key
    │
    ├── credential record AEAD
    ├── credential record AEAD
    └── credential record AEAD
```

The passphrase-derived key does not directly encrypt each record. This permits
a future passphrase change to re-wrap the vault key without re-encrypting every
credential.

## Password KDF

Use Argon2id with explicit parameters stored in the format.

Initial policy target:

- 64 MiB memory;
- 3 passes;
- 128-bit random salt;
- 256-bit KEK.

These values reflect the memory-constrained RFC 9106 recommendation and can be
raised for newly created vaults after measured qualification.

### Hostile KDF parameters

Vault files are attacker-controlled input.

Hard upper and lower limits must be validated **before** invoking Argon2id.
A file must not be able to request arbitrary memory, iteration count, output
length, or allocation size.

## Authenticated encryption

Use XChaCha20-Poly1305-IETF.

Every encryption uses a fresh random 192-bit nonce.

Decryption must never expose plaintext before authentication succeeds.

Authenticated associated data includes, at minimum:

- format domain/version;
- vault identifier;
- record identifier;
- record type/version.

## File format

The format is versioned, bounded, and canonical.

Required structural data includes:

- fixed magic;
- version;
- KDF identifier/version and bounded parameters;
- random KDF salt;
- authenticated wrapped vault key;
- random vault identifier;
- bounded record table;
- per-record nonce, ciphertext and authentication tag.

No credential plaintext appears in the file.

Metadata that need not be visible while locked should remain encrypted.

All lengths/counts are validated before allocation or cryptographic work.

## Persistence

No plaintext temporary file is permitted.

Updates use a complete encrypted replacement in the same directory, followed by
the strongest practical flush + atomic replacement sequence for the platform.

The implementation must address:

- partial writes;
- interruption/crash;
- truncation;
- unsupported versions;
- malformed lengths/counts;
- duplicate identifiers;
- concurrent writers;
- symlink/reparse-point destination attacks;
- owner/file-permission policy.

Filesystem permissions are defense in depth; vault confidentiality never
depends on file secrecy.

## Passphrase and key memory

Passphrases enter through secret-byte ownership, not ordinary `string` APIs.

Derived keys and unwrapped vault keys use controlled memory and are cleared
immediately when their lifetime ends.

credentials-d cannot erase copies that existed before the passphrase or secret
entered the library.

## Lock semantics

A locked vault retains no usable vault decryption key in backend-owned memory.

Unlock derives the KEK, authenticates/decrypts the wrapped vault key, then
retains only the vault key required for the unlocked session.

Lock clears the retained vault key.

Wrong passphrase and authenticated tamper both fail closed and never expose
record plaintext.

## Rollback

AEAD does not detect restoration of an older, previously valid vault file.

Rollback is an explicit residual risk in the first format.

A real anti-rollback mechanism would require trusted state outside the vault and
must be separately designed. An unauthenticated counter inside the same file is
not an anti-rollback mechanism.

Application-side credential revocation/rotation remains necessary after
suspected disclosure.

## Required verification

Before production admission:

- libsodium initialization/runtime qualification;
- KDF/AEAD primitive sanity vectors;
- create/open/reopen;
- lock/unlock;
- binary secrets including embedded NUL;
- wrong passphrase;
- changed salt/KDF metadata;
- modified nonce/ciphertext/tag/associated data;
- truncation at structural boundaries;
- hostile KDF parameters rejected before KDF work;
- duplicate/corrupt record identifiers;
- replace/delete/notFound;
- atomic-write recovery;
- concurrent-access/locking;
- parser fuzz corpus;
- sentinel leak tests;
- DMD and LDC qualification.

## Consequences

The encrypted vault is a distinct explicit backend. It is never selected
implicitly when a native OS store is unavailable.

The root package and native platform backends do not gain a libsodium dependency
merely because the optional vault exists.

## References

- libsodium documentation: https://doc.libsodium.org/
- libsodium initialization: https://doc.libsodium.org/usage
- libsodium password hashing: https://doc.libsodium.org/password_hashing
- libsodium XChaCha20-Poly1305:
  https://doc.libsodium.org/secret-key_cryptography/aead/chacha20-poly1305
- RFC 9106: https://www.rfc-editor.org/rfc/rfc9106.html
- Botan security documentation:
  https://botan.randombit.net/handbook/security.html
- historical D sodium binding:
  https://github.com/carblue/sodium
