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

The design makes unsafe handling difficult rather than merely documenting that
consumers should be careful. Owned secret plaintext lives in non-GC memory,
`SecretBuffer` is non-copyable, plaintext exposure is explicit and scoped, and
zeroization uses compiler-recognized volatile stores. Persistence remains behind
an explicit store boundary.

Platform credential stores are expected to be the normal persistence mechanism.
An encrypted file vault is a possible additional backend, not the definition of
the library. Backend failure never silently downgrades to plaintext or another
weaker store.

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
    CredentialNamespace,
    CredentialStatus,
    MemoryCredentialStore,
    SecretBuffer;

CredentialNamespace ns;
assert(CredentialNamespace.tryParse("org.example.application", ns));

auto store = new MemoryCredentialStore(ns);
auto secret = SecretBuffer(cast(const(ubyte)[]) "token");

CredentialHandle handle;
assert(store.store(secret, handle) == CredentialStatus.ok);

assert(store.acquire(handle, (scope const(ubyte)[] bytes) @safe
{
    // Use plaintext only inside this explicit acquisition callback.
}) == CredentialStatus.ok);

assert(store.remove(handle) == CredentialStatus.ok);
```

`CredentialHandle.serialize()` and `CredentialNamespace` are non-secret and
may be persisted in ordinary application settings. Credential plaintext may
not.

`SecretBuffer` owns a non-GC allocation, cannot be copied, and clears its owned
allocation using `core.volatile.volatileStore` before release. This guarantees
zeroization of that allocation against dead-store elimination; it does not
erase the caller's source buffer or copies made by external code.

`MemoryCredentialStore` is deterministic, ephemeral and thread-confined. It is
a contract/reference backend, not a persistent security mechanism. It requires
an explicit namespace and rejects handles from another store instance.

See [ADR 0002](docs/adr/0002-credential-store-public-contract.md) for the
original API semantics and [ADR 0003](docs/adr/0003-core-security-hardening.md)
for the hardened ownership and backend contract.

## Native backends

Native credential stores are explicit DUB subpackages. The core package never
silently selects a backend or falls back to weaker persistence.

### Linux Secret Service

Linux desktop consumers can opt into:

```text
credentials-d:linux-secret-service
```

and create:

```d
import credentials : CredentialNamespace;
import credentials.backend.secret_service : LinuxSecretServiceStore;

CredentialNamespace ns;
assert(CredentialNamespace.tryParse("org.example.application", ns));

auto store = new LinuxSecretServiceStore(ns);
```

The backend uses libsecret with one retained Secret Service session, binary
`SecretValue` payloads, opaque namespace/locator attributes, all-result lookup
with ambiguity rejection, and explicit `unavailable` behavior when no service
is reachable. Synchronous operations may block or prompt and must not run on a
GUI/render thread.

See [ADR 0005](docs/adr/0005-linux-secret-service.md).

### Windows Credential Manager

Windows consumers can opt into:

```text
credentials-d:windows
```

and create:

```d
import credentials : CredentialNamespace;
import credentials.backend.windows : WindowsCredentialStore;

CredentialNamespace ns;
assert(CredentialNamespace.tryParse("org.example.application", ns));

auto store = new WindowsCredentialStore(ns);
```

The backend uses Generic Credentials with local-machine persistence for the
current Windows user, validates the 2560-byte blob limit before native calls,
uses opaque OS-CSPRNG record identifiers, and wipes plaintext returned by
`CredReadW` before `CredFree`.

It does not claim hardware-backed or Credential Guard protection, and it does
not silently fall back when Windows Credential Manager is unavailable.

See [ADR 0004](docs/adr/0004-windows-credential-manager.md).

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
