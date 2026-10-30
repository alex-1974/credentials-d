# ADR 0002 — CredentialStore and Secret public contracts

**Status:** Accepted historically; SecretBuffer and capability details superseded by ADR 0003  
**Date:** 2026-10-30

> **Update:** ADR 0003 replaces the GC-backed `SecretBuffer` representation,
> store input signatures, namespace semantics, status taxonomy and capability
> model established during this initial API qualification. The separation of
> handles, explicit plaintext acquisition, store boundary, replacement and
> deletion semantics remains in force.

## Context

ADR 0001 and the threat model establish that credential plaintext is a
security-sensitive asset, while credential handles are non-secret application
state.

The first public API must let consumers persist, acquire, replace and remove
credentials without turning credentials-d into an OAuth framework, password
manager, crypto toolkit, or application authorization layer.

The API must also leave room for materially different backends:

- ephemeral memory;
- deterministic mocks;
- Linux Secret Service;
- Windows Credential Manager;
- macOS Keychain;
- a possible later encrypted vault.

## Decision

### SecretBuffer

`SecretBuffer` is the explicit plaintext-owning type.

The initial implementation is a final class containing one mutable,
GC-managed byte array.

This choice is deliberate for the pre-0.1 contract phase:

- copying a class reference does not duplicate plaintext bytes;
- ownership is object identity rather than fragile move-only struct semantics;
- `clear()` gives consumers an explicit prompt-lifetime endpoint;
- the destructor performs the same best-effort overwrite;
- manual allocation, pinning and foreign secure-memory APIs are deferred until
  they can be qualified independently.

This implementation does **not** claim strong deterministic zeroization. The
public contract permits the internal representation to change later without
changing consumer code.

Plaintext access is explicit through:

```d
secret.withBytes((scope const(ubyte)[] bytes) {
    // use bytes here
});
```

There is no public raw-byte property and no implicit conversion to `string`.

Accidental formatting is redacted rather than exposing plaintext.

### CredentialHandle

`CredentialHandle` is an opaque, non-secret reference to one logical
credential record.

Handles:

- contain no credential plaintext when produced by credentials-d;
- may be persisted in ordinary application settings;
- have an opaque serialized form;
- may be reconstructed from that serialized form;
- must not be interpreted by consumers for identity or authorization policy.

The initial parser uses a narrow single-line ASCII grammar and bounded length.

### CredentialStore

`CredentialStore` defines four state-changing/access operations:

```text
store
acquire
replace
remove
```

`acquire` does not return a general plaintext object. Instead it invokes a
scoped `SecretVisitor` exactly once on success.

Normal backend outcomes use `CredentialStatus`:

```text
ok
notFound
locked
unsupported
invalidInput
backendError
```

Exceptions are not the normal not-found/locked/error protocol and may still
propagate for exceptional runtime failures such as allocation failure or from
consumer callbacks.

### Capabilities

Backend properties are queried through `StoreCapabilities`.

The initial capability set distinguishes:

- persistent storage;
- lock support;
- application-controlled unlock;
- user-presence support;
- hardware-backed protection;
- native OS credential service;
- confirmation of logical deletion;
- thread-confined versus thread-safe operation.

A false capability is not an error. Consumers must not infer a property that
the backend does not report.

### Concurrency

The common interface does not promise thread safety.

Every backend reports its concurrency contract. The bootstrap memory and mock
stores are thread-confined.

### Replacement

Replacement is handle-stable: the same handle continues to identify the
logical credential record.

The old plaintext is never returned as a side effect of replacement.

### Removal

Removal makes a logical record unavailable through that store. It does not
promise physical secure erasure beyond a backend's documented guarantees.

## Test backends

`MemoryCredentialStore` is an ephemeral deterministic backend used for
contract qualification and consumers that explicitly want memory-only storage.

`credentials.testing.MockCredentialStore` delegates normal behavior to the
memory store and can force operation statuses such as `locked` or
`backendError`.

The shared contract suite is written against the `CredentialStore`
interface so later platform backends can run the same baseline behavior tests.

## D enforcement boundary

The API uses D where the language can provide useful enforcement:

- no implicit `SecretBuffer -> string` conversion;
- no public raw-byte property;
- scoped callback plaintext access;
- compile-negative escape test under DIP1000;
- external consumer compilation through the package root.

Some properties remain semantic rather than compiler-enforced:

- a consumer can deliberately copy bytes inside the explicit callback;
- a consumer can keep a `SecretBuffer` reference alive;
- GC/runtime/compiler behavior prevents a universal secure-zeroization claim.

Those limits are documented rather than hidden.

## Consequences

The first public API is intentionally small and application-independent.

OS backends can now be researched against a concrete semantic contract.

A later secure-memory implementation may replace `SecretBuffer` internals,
but it must preserve the public plaintext-access contract unless a new ADR
justifies an API break during the 0.x period.
