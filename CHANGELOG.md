# Changelog

All notable changes to this project will be documented here.

## Unreleased

- Publish the generated consumer DDOX documentation through GitHub Pages and
  use the Pages site as the package homepage.

- Publish consumer-facing Ddoc/DDOX documentation through GitHub Pages, with
  separate API sections for core, Linux, Windows, macOS, encrypted vault and
  security-key support.
- Point the DUB package homepage to the published documentation site.

## v0.1.0 — 2026-10-31

First public release.

For application developers:

- one common `CredentialStore` workflow for saving, reading, updating and
  removing credentials;
- persistent platform stores for Linux, Windows and macOS;
- a portable `EncryptedCredentialVault` for applications that deliberately
  want their own vault file;
- optional security-key unlock for encrypted vaults;
- opaque `CredentialHandle` and `VaultUnlockMethod` values that can be kept
  in normal application settings;
- explicit `CredentialStatus` results and `StoreCapabilities` for UI and
  scheduling decisions;
- public consumer modules with implementation modules kept outside the
  compatibility contract;
- buildable examples for the basic store, encrypted vault and security-key
  workflows;
- Ddoc/DDOX documentation and CI examples aligned with the public consumer API.

Qualification status:

- Linux, Windows, encrypted-vault and the tested physical security-key paths
  have qualification coverage;
- macOS is compiled and fail-closed tested in CI, but final production
  qualification still requires a properly signed/provisioned macOS
  application context.

- Add buildable consumer examples for the core store, encrypted vault and
  security-key vault unlock flows; CI and release gates now compile/run these
  examples as public-API smoke tests.
- Run the encrypted-vault gate on `main` as well as `develop` so release
  candidates exercise the vault consumer path.

- Rewrite README and public Ddoc/DDOX documentation from a consumer perspective:
  show what each API is for, how to use it, and realistic examples before
  implementation detail.
- Filter `credentials.backend.*` from generated DDOX documentation and add a
  CI smoke build for the consumer-facing DDOX output.

- Freeze the intended pre-0.1 consumer surface in `docs/API_STABILITY.md` and
  complete Ddoc contracts/examples for the core store, value types, vault and
  security-key facade.
- Hide vault protector kind/binding accessors from the consumer surface; they
  remain backend implementation details.

- Improve pre-0.1 consumer ergonomics with direct `CredentialNamespace(...)`
  construction, clearer operation-status names, slimmer store capabilities and
  public `credentials.linux`, `credentials.windows` and
  `credentials.macos` facades.

- Redesign the pre-0.1 public API around consumer terminology: `save()`,
  `withSecret()`, `update()`, `EncryptedCredentialVault`,
  `VaultUnlockMethod`, and the `credentials.security_key` facade.
- Move protocol-level FIDO2/CTAP and low-level vault protector terminology out
  of the consumer package surface; public security-key access is expressed as
  `touch` or `verifiedUser`.

- Add generic authenticated external vault-key envelopes with multiple-wrapper
  and passphrase-recovery semantics.
- Add an optional FIDO2 hmac-secret vault-key protector through a narrow
  libfido2 FFI, with explicit user-presence / UV policy and transient
  SecretBuffer PIN handling.
- Add a no-hardware libfido2 ABI/discovery gate for DMD and LDC.

- Add concurrent encrypted-vault writer and crash-residue regression coverage.
- Add a package-private libFuzzer-compatible vault-header parser target and compile it in the vault security gate.

- Gate native credential backends and encrypted-vault security checks on release candidates targeting `main`.
- Add a bounded malformed-vault header corpus covering structural truncation, invalid KDF costs, lengths, namespace syntax and trailing data before key derivation.

- Bootstrap repository and package identity.
- Establish initial security scope and roadmap.
- Define the first public `SecretBuffer`, `CredentialHandle`, and
  `CredentialStore` contracts.
- Add deterministic memory/mock stores, shared contract tests, and compile
  negative secret-handling tests.
- Harden `SecretBuffer` with non-GC ownership, non-copyable value semantics,
  volatile zeroization and deterministic normal-scope destruction.
- Add validated credential namespaces and store-instance handle isolation.
- Refine backend errors and capabilities; prohibit silent insecure fallback.
- Carry secret ownership and scope-negative tests into the release gate.
- Add qualified OS-CSPRNG record locators for Linux, Windows and macOS.
- Add an explicit Windows Credential Manager backend subpackage with native integration tests.
- Add an explicit Linux Secret Service/libsecret backend with binary-secret and unavailable-service integration tests.
- Add an explicit macOS Data Protection Keychain backend with fail-closed entitlement qualification and a signed-consumer release requirement.
