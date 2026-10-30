# Changelog

All notable changes to this project will be documented here.

## Unreleased

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
