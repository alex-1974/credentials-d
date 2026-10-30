# ADR 0005 — Linux Secret Service backend

**Status:** Accepted for Issue #13 implementation  
**Date:** 2026-10-30

## Context

Linux desktop applications commonly use the freedesktop.org Secret Service API.
The service is provided by implementations such as GNOME Keyring or KWallet.

The Secret Service security model differs from application-managed encryption:

- the desktop credential service owns persistence and unlock policy;
- attributes used for item lookup are metadata and are not confidential;
- synchronous API calls may block and may require user interaction;
- provider behavior can vary across desktop environments;
- the service may be absent in headless or minimal sessions.

credentials-d must use this platform facility without inventing stronger
guarantees or silently falling back to weaker persistence.

## Decision

The Linux backend is an explicit DUB subpackage:

```text
credentials-d:linux-secret-service
```

It uses libsecret. credentials-d does not implement the Secret Service D-Bus
protocol directly.

### Service/session lifetime

Each `LinuxSecretServiceStore` opens one independent `SecretService` proxy
with `SECRET_SERVICE_OPEN_SESSION` and reuses it for the lifetime of the store.

Operations are serialized per store instance.

This avoids repeatedly creating D-Bus/OpenSession state for every credential
operation and keeps the native session lifetime explicit.

### Schema and metadata

The backend uses one fixed schema with exactly two string attributes:

```text
namespace
credential
```

The values are:

- the validated non-secret `CredentialNamespace`;
- a 128-bit OS-CSPRNG locator encoded as lowercase hexadecimal.

No profile name, service username, email address, OAuth scope, project name or
credential plaintext is stored in attributes.

The human-readable item label is deliberately generic.

### Binary secret representation

Credential plaintext is passed through libsecret `SecretValue` with an
explicit byte length and `application/octet-stream` content type.

The backend does not require credentials to be UTF-8 or NUL-terminated strings.

The native integration test includes an embedded NUL byte to enforce this
contract.

### Lookup and ambiguity

All exact-record searches include `SECRET_SEARCH_ALL`.

The backend counts matching items:

```text
0 -> notFound
1 -> continue
>1 -> ambiguous
```

It never selects the first item from an ambiguous result set.

Search attributes are namespace + random locator, so accidental duplicates are
already extraordinarily unlikely; explicit ambiguity handling protects against
corrupt, migrated or hostile metadata.

### Unlock and interaction

Acquire/replace/delete may request unlock through libsecret.

The backend reports:

- unlock model: OS-managed;
- blocking: mayPrompt.

Synchronous libsecret operations may block indefinitely. Applications with a
GUI must execute this store away from the GUI/render thread.

credentials-d does not embed a GUI/event-loop abstraction.

### Returned plaintext

libsecret owns plaintext inside a `SecretValue`.

The backend:

1. obtains or loads the exact item's `SecretValue`;
2. exposes its bytes only through the scoped `SecretVisitor`;
3. unrefs the `SecretValue` immediately after the visitor returns.

The backend cannot guarantee how the Secret Service implementation manages its
own internal plaintext copies.

### Errors

Native `GError` messages are never surfaced through the public API.

Known Secret Service / GIO conditions are mapped to the common non-secret
status model, including:

- locked;
- notFound;
- ambiguous;
- userCancelled;
- permissionDenied;
- unsupported;
- unavailable.

Unknown native failures become `backendFailure`.

The `GError` object is freed after classification.

### Mobility

The generic Secret Service specification does not guarantee that every provider
is strictly local-device-only or incapable of synchronization.

The backend therefore conservatively reports `StoreMobility.mayRoam`.

A future provider-specific backend may advertise a narrower property only if
that property is independently established.

### No fallback

If the session bus, Secret Service provider or required native capability is
unavailable, the backend returns `unavailable`.

It never writes a plaintext file, switches to another provider abstraction, or
selects an encrypted vault automatically.

## Residual risks

The library does not protect against:

- hostile code running as the same OS user while the provider permits access;
- root or a compromised desktop session;
- provider-specific backups or synchronization not represented by the generic
  Secret Service API;
- plaintext copies retained internally by the provider;
- application code deliberately copying bytes inside `SecretVisitor`.

Prompt behavior and unlock policy remain properties of the active Secret
Service implementation.

## Verification

The Linux gate runs on Ubuntu with libsecret and GNOME Keyring in an isolated
D-Bus session under both DMD 2.111.0 and LDC 1.41.0.

It verifies:

- absence of a reachable session bus fails closed as `unavailable`;
- native store/acquire;
- binary secret round-trip including an embedded NUL;
- reopening through a fresh backend instance;
- replacement;
- namespace rejection;
- deletion and subsequent `notFound`;
- explicit cleanup of the isolated keyring session.

Ambiguity is enforced by the implementation's all-results cardinality check.
A real duplicate-provider fixture may be added if a test provider exposes a
stable API for deliberately creating duplicate schema/attribute records without
normal store-update semantics.
