# API stability

credentials-d v0.1.0 defines the first public consumer API.

This document defines which source-level interfaces are intended for consumers
and which namespaces remain implementation details.

## Public API

The supported consumer surface is:

- `credentials`
  - `CredentialHandle`
  - `CredentialNamespace`
  - `CredentialStatus`
  - `CredentialStore`
  - `SecretBuffer`
  - `SecretCallback`
  - `StoreCapabilities` and its public enums
  - `MemoryCredentialStore`
- `credentials.linux`
  - `LinuxCredentialStore`
- `credentials.windows`
  - `WindowsCredentialStore`
- `credentials.macos`
  - `MacOSCredentialStore`
- `credentials.vault`
  - `EncryptedCredentialVault`
  - `VaultUnlockMethod`
- `credentials.security_key`
  - `SecurityKeyInfo`
  - `SecurityKeyCapabilities`
  - `SecurityKeyAccess`
  - `findSecurityKeys()`
  - `getSecurityKeyCapabilities()`
  - `addSecurityKeyUnlock()`
  - `unlockWithSecurityKey()`

Consumers should import these modules rather than implementation modules.

## Internal API

Anything under `credentials.backend.*` is an implementation namespace.

It may expose D symbols because D modules need to cooperate across subpackages,
qualification programs and integration tests. Those symbols are not part of
the consumer compatibility contract.

In particular, the following concepts are intentionally internal:

- FIDO2/CTAP commands, policies and bindings;
- hmac-secret and hmac-secret-mc;
- COSE algorithms;
- native security-key device paths;
- vault image/header structures;
- vault wrapping-key sources;
- protector kinds/bindings/salts;
- platform FFI declarations.

Documentation may discuss these concepts to explain security or qualification,
but consumer code should not depend on them.

## Stability policy

Starting with `v0.1.0`:

- patch releases should not intentionally break documented public source APIs;
- minor 0.x releases may still make incompatible changes when necessary, but
  such changes must be documented prominently in the changelog and release
  notes;
- opaque serialized formats such as credential handles and vault unlock methods
  are versioned independently from D source APIs and must fail closed when an
  unsupported format is encountered;
- implementation modules remain free to change without compatibility promises.

No compatibility guarantee is made for importing symbols from
`credentials.backend.*`.

## Consumer rules

Applications should:

1. create one stable `CredentialNamespace` for their credential domain;
2. persist `CredentialHandle.serialize()` or `VaultUnlockMethod.serialize()`
   only as opaque non-secret data;
3. reconstruct persisted values with their respective `tryParse()` functions;
4. inspect `StoreCapabilities` rather than infer behavior from the operating
   system or backend name;
5. handle `CredentialStatus` explicitly and never assume an unavailable
   backend silently falls back to weaker storage;
6. keep plaintext use inside `withSecret()` / `SecretBuffer.withBytes()`
   callbacks;
7. avoid relying on runtime security-key ids across reconnects or reboots.

## Qualification status

The v0.1.0 public API is covered by consumer compile/run gates on the supported
compiler baseline.

Platform qualification is separate from source API stability. In particular,
the macOS Data Protection Keychain implementation is compiled and fail-closed
tested in CI, but still requires a properly signed/provisioned macOS application
context for final production qualification.
