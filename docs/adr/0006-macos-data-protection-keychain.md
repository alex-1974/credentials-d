# ADR 0006 — macOS Data Protection Keychain backend

**Status:** Accepted for Issue #15 implementation  
**Date:** 2026-10-30

## Context

macOS exposes two materially different keychain models:

- the legacy file-based keychain;
- the Data Protection Keychain (DPK), which uses the modern SecItem model and
  keychain access groups.

Apple recommends setting `kSecUseDataProtectionKeychain = true` for modern
macOS SecItem operations unless legacy keychain compatibility is specifically
required.

The DPK derives accessible keychain groups from code-signing entitlements and
their provisioning context. This is a real application deployment requirement,
not a detail credentials-d can bypass.

## Decision

The production macOS backend is an explicit DUB subpackage:

```text
credentials-d:macos-data-protection
```

It never silently falls back to the file-based keychain.

### Item class

Credentials use `kSecClassGenericPassword`.

The primary routing metadata is:

- service: fixed credentials-d prefix + validated application namespace;
- account: 128-bit OS-CSPRNG locator.

Both are non-secret.

No OSM username, display name, email, OAuth scope, project name or credential
plaintext is stored in keychain attributes.

### Data Protection Keychain selection

Every query, add, update and delete dictionary contains:

```text
kSecUseDataProtectionKeychain = true
kSecAttrSynchronizable        = false
```

Synchronization is therefore explicitly disabled rather than relying on an
implicit default.

### Accessibility

New records use:

```text
kSecAttrAccessibleWhenUnlockedThisDeviceOnly
```

This is appropriate for foreground desktop credential use:

- plaintext is unavailable while the device is locked;
- records do not migrate to another device through backup/restore;
- iCloud synchronization is separately disabled.

A future background-service use case would require a separate reviewed
accessibility policy rather than weakening this backend silently.

### User presence

The default backend does not require `SecAccessControl` user presence and
reports `supportsUserPresence = false`.

A biometric/passcode-gated variant can be added later as an explicit policy
backend if a real consumer needs it.

### Secret input lifetime

`SecretBuffer` bytes are copied into a short-lived CoreFoundation-owned
immutable `CFData` using `CFDataCreate`.

This is intentional. Apple's no-copy constructor does not guarantee that an
internal copy is avoided, while an externally backed CFData adds another
lifetime/allocator boundary to a security-sensitive FFI. macOS LDC
qualification also exposed an intermittent teardown fault on that path.

`SecItemAdd` / `SecItemUpdate` are invoked synchronously and the temporary
CFData is released immediately afterwards.

The credentials-d-owned `SecretBuffer` remains non-GC and independently
zeroized. CoreFoundation and Security.framework internal copies are outside
credentials-d's zeroization guarantee.

### Secret output lifetime

`SecItemCopyMatching` returns a retained `CFData` containing plaintext.

The backend:

1. validates the returned CoreFoundation type;
2. exposes the bytes only through the scoped `SecretVisitor`;
3. releases the returned `CFData` immediately afterwards.

credentials-d cannot guarantee zeroization of Security.framework's internal
returned allocation.

### Store/update/delete semantics

`store` uses `SecItemAdd`; duplicate primary-key state does not overwrite an
existing credential. A fresh CSPRNG locator is generated and retried.

`replace` uses `SecItemUpdate`; missing records return `notFound` rather
than being created.

`remove` uses `SecItemDelete` on the exact service/account pair.

The SecItem primary key prevents duplicate generic-password items with the same
visible service/account/access-group/synchronization identity, so this backend
does not depend on first-match ambiguity semantics.

### Capabilities

The backend reports:

- persistent: yes;
- protection: native user credential store;
- unlock: OS-managed;
- user presence: no;
- mobility: local device;
- logical deletion confirmation: yes;
- blocking: may block;
- concurrency: serialized.

It does not claim:

- Secure Enclave storage;
- generic hardware-backed protection;
- per-Dunia-profile cryptographic isolation;
- protection against hostile code already authorized in the same effective
  keychain access group;
- physical secure deletion from system backups/snapshots outside the DPK
  contract.

### Signing and entitlement boundary

Data Protection Keychain access groups are derived from code-signing
entitlements. Apple documents that these entitlements must be authorized by a
provisioning profile for the application environment.

credentials-d therefore treats missing/restricted entitlement errors as
`permissionDenied`.

It does not switch to the legacy file-based keychain when this happens.

## CI qualification

The macOS hosted-runner gate always compiles and executes the native backend.

The hosted runner is explicitly marked as an **unprovisioned command-line
host**. Apple documents that the restricted Data Protection Keychain
entitlements require an app-like bundle plus provisioning authorization.

In that deliberately non-production context, the gate accepts only:

1. full store/read/reopen/replace/delete integration; or
2. a fail-closed first write that produces no handle.

Observed toolchains may be rejected by Security.framework at different stages:
DMD currently reaches `permissionDenied`, while LDC 1.41 may receive
`errSecParam` / `invalidInput` in the unprovisioned CLI host. The latter is
accepted **only** when the CI fixture explicitly marks this exact
unprovisioned context.

The backend itself keeps `errSecParam -> invalidInput`. A normal or
production-signing integration run never treats `invalidInput` as an
entitlement error.

The gate also emits the executable's code-signing/entitlement diagnostics so
changes in the hosted-runner signing context are visible.

A hosted fail-closed outcome is **not** a production integration
qualification.

Before a release advertises the macOS DPK backend as production-qualified, the
same integration fixture must pass in a properly signed app-like macOS
consumer with its real keychain-access entitlement/provisioning context.

## Failure mapping

Public errors contain no Security.framework text.

Relevant OSStatus values map to:

- item not found -> `notFound`;
- duplicate item -> `ambiguous` during locator collision handling;
- locked/data unavailable -> `locked`;
- interaction required -> `interactionRequired`;
- user cancel -> `userCancelled`;
- missing/restricted entitlement, auth failure, read-only -> `permissionDenied`;
- no keychain -> `unavailable`;
- data too large -> `tooLarge`;
- decode failure -> `corruptData`;
- other failures -> `backendFailure`.

## References

- Apple, `kSecUseDataProtectionKeychain`
- Apple TN3137, *On Mac keychain APIs and implementations*
- Apple, *Restricting keychain item accessibility*
- Apple, *Sharing access to keychain items among a collection of apps*
