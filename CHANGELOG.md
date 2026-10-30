# Changelog

All notable changes to this project will be documented here.

## Unreleased

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
