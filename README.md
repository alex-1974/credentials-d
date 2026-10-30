# credentials-d

Secure credential storage for D applications.

`credentials-d` is a small, application-independent library for storing and
retrieving high-value application credentials without placing those secrets in
ordinary settings files.

The motivating consumer is Dunia, but OpenStreetMap, OAuth, HTTP and application
profile management are deliberately outside this package.

## Status

Pre-0.1 API qualification.

The first credential-store contract is implemented and tested, but remains
subject to 0.x refinement. No platform credential backend or encrypted-vault
backend has been selected.

## Intended scope

The library is expected to own:

- opaque credential identifiers and handles;
- controlled secret ownership and lifetime;
- a common credential-store contract;
- deterministic memory/mock backends for contract testing;
- Linux Secret Service, Windows Credential Manager and macOS Keychain adapters;
- optionally, an application-controlled encrypted-vault backend if its need and
  cryptographic dependency are independently qualified.

It does not aim to provide:

- OAuth authorization flows;
- HTTP clients;
- OpenStreetMap identity or upload policy;
- a password manager;
- certificate management;
- a general-purpose cryptographic toolkit;
- custom cryptographic primitives.

## Security direction

Credentials are security-sensitive data.

The design should make unsafe handling difficult rather than merely documenting
that consumers should be careful. In particular, the public API should avoid
requiring secrets to become ordinary GC-managed strings, should not make
formatting/logging of secrets convenient, and should keep persistence behind an
explicit store boundary.

Platform credential stores are expected to be the normal persistence mechanism.
An encrypted file vault is a possible additional backend, not the definition of
the library.

No cryptographic backend decision has been made. Botan, libsodium or another
implementation must be qualified against the exact narrow primitive set needed
before an encrypted-vault backend is admitted.

See [ADR 0001](docs/adr/0001-security-scope.md) for the initial scope,
[Threat Model and Security Contract](docs/security/THREAT_MODEL.md) for the
normative security boundary, and [SECURITY.md](SECURITY.md) for vulnerability
reporting.


## Public API prototype

The first public contract separates persistable handles from plaintext:

```d
import credentials :
    CredentialHandle,
    CredentialStatus,
    MemoryCredentialStore,
    SecretBuffer;

auto store = new MemoryCredentialStore;
auto secret = new SecretBuffer(cast(const(ubyte)[]) "token");

CredentialHandle handle;
assert(store.store(secret, handle) == CredentialStatus.ok);

assert(store.acquire(handle, (scope const(ubyte)[] bytes) @safe
{
    // Use plaintext only inside this explicit acquisition callback.
}) == CredentialStatus.ok);

assert(store.remove(handle) == CredentialStatus.ok);
```

`CredentialHandle.serialize()` is intended for normal application settings.
Credential plaintext is not.

`SecretBuffer` currently uses GC-managed mutable storage and best-effort
overwrite on `clear()`; this is deliberately **not** documented as guaranteed
secure zeroization. The representation can be strengthened later without
changing the consumer-facing acquisition contract.

`MemoryCredentialStore` is deterministic, ephemeral and thread-confined. It is
a contract/reference backend, not a persistent security mechanism.

See [ADR 0002](docs/adr/0002-credential-store-public-contract.md) for the API
semantics.

## Compatibility baseline

Minimum supported D frontend:

```text
2.111.0
```

Normal development is checked with:

```text
DMD 2.111.0
LDC 1.41.0
```

The main-branch release gate additionally exercises the workspace release
compiler matrix.

## Development

```bash
dub test --compiler=dmd --force
dub test --compiler=ldc2 --force
dub run --root=tests/consumer --compiler=dmd --force
```

Normal integration targets `develop`. `main` is reserved for qualified release
state.

## License

MIT.
