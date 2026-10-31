# credentials-d

Secure credential storage for D applications.

`credentials-d` is a small, application-independent library for storing and
retrieving high-value application credentials without placing those secrets in
ordinary settings files.

The motivating consumer is Dunia, but OpenStreetMap, OAuth, HTTP and application
profile management are deliberately outside this package.

## Status

Pre-0.1 API qualification.

The semantic core, native desktop credential-store backends and optional
encrypted-vault backend are implemented and security-gated. The API remains
subject to 0.x refinement; the macOS Data Protection Keychain still requires a
signed app-like production qualification.

## Intended scope

The library is expected to own:

- opaque credential identifiers and handles;
- controlled secret ownership and lifetime;
- a common credential-store contract;
- deterministic memory/mock backends for contract testing;
- Linux Secret Service, Windows Credential Manager and macOS Keychain adapters;
- an optional application-controlled encrypted-vault backend using a qualified
  narrow libsodium boundary;
- optional hardware-assisted vault-key protectors such as FIDO2 hmac-secret.

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
An encrypted file vault is an explicit additional backend, not the definition
of the library. Backend failure never silently downgrades to plaintext or
another weaker store.

The optional encrypted vault uses official libsodium through a narrow private
FFI: Argon2id for the passphrase wrapper and XChaCha20-Poly1305-IETF for
authenticated encryption. Optional FIDO2 support is a vault-key protector,
never a CredentialStore and never a place to store application credentials.

See [ADR 0001](docs/adr/0001-security-scope.md) for the initial scope,
[Threat Model and Security Contract](docs/security/THREAT_MODEL.md) for the
normative security boundary, [Native platform credential-store
qualification](docs/security/PLATFORM_STORES.md) for the OS backend comparison,
and [SECURITY.md](SECURITY.md) for vulnerability reporting.


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

### macOS Data Protection Keychain

macOS application consumers can opt into:

```text
credentials-d:macos-data-protection
```

and create:

```d
import credentials : CredentialNamespace;
import credentials.backend.macos :
    MacOSDataProtectionCredentialStore;

CredentialNamespace ns;
assert(CredentialNamespace.tryParse("org.example.application", ns));

auto store = new MacOSDataProtectionCredentialStore(ns);
```

Every operation explicitly targets the Data Protection Keychain, disables
synchronization, and new records use
`kSecAttrAccessibleWhenUnlockedThisDeviceOnly`. Missing signing/keychain
entitlements fail closed; the backend never switches to the legacy file-based
keychain.

A final production qualification must run the integration fixture inside the
consumer's properly signed/provisioned macOS application context.

See [ADR 0006](docs/adr/0006-macos-data-protection-keychain.md).

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


## FIDO2 vault unlock

Hardware-assisted vault unlock is available through the optional:

```text
credentials-d:fido2-vault
```

FIDO2 is deliberately **not** another credential store. A FIDO2 authenticator
never receives OAuth tokens, API keys or vault records. Instead, a dedicated
FIDO2 credential uses the CTAP `hmac-secret` extension to derive a
credential-scoped 32-byte wrapping key. That key authenticates and unwraps the
same random vault key already used by the encrypted vault.

The encrypted-vault format remains unchanged. Additional unlock methods are
stored as independent non-secret `VaultUnlockEnvelope` values, so one vault
may retain:

```text
random vault key
├── existing passphrase / Argon2id recovery wrapper
├── FIDO2 security key A envelope
└── FIDO2 backup key B envelope
```

Two interaction policies are explicit:

- `touchOnly` (wire-compatible alias of `userPresence`): normal vault
  unlock is authenticator presence plus physical touch, with no PIN/UV request;
  older authenticators may still require a PIN once during MakeCredential;
- `userVerificationRequired`: UV required and enrollment requests
  `credProtect=UV_REQUIRED`; unsupported authenticators fail rather than
  silently downgrading.

Authenticator device paths are runtime selectors and are never persisted as
security identity. RP id, opaque credential id and verification policy form the
persisted non-secret FIDO2 binding.

Consumers may query standard authenticator capabilities without creating a
credential or requesting user interaction:

```d
Fido2Capabilities capabilities;
auto status = queryFido2Capabilities(devicePath, capabilities);
```

The result reports hmac-secret and hmac-secret-mc, credProtect, client-PIN and
built-in UV availability/configuration, UV modality, discoverable-credential
support/capacity, and advertised COSE algorithms (ES256, EdDSA, ES384 and
RS256). Capability discovery is advisory; actual enrollment and unlock calls
continue to fail closed if a requested policy cannot be satisfied.

FIDO2 operations use official libfido2 through a narrow private FFI and are
synchronous; applications must execute enrollment/unlock away from a GUI/render
thread. PIN overloads accept `SecretBuffer`, create only one temporary
NUL-terminated native buffer, and overwrite it before release. A PIN-protected
CTAP2.0 authenticator may require this overload for MakeCredential even when
the persisted binding remains `userPresence`; later hmac-secret derivation
still occurs without PIN/UV.

CI qualifies the ABI, parsing, envelope cryptography and no-hardware discovery
path. The physical-authenticator contract was qualified on 2026-10-31 with a
YubiKey 5.2.4 for hmac-secret, touch-only/user-presence, UV/PIN, wrong
credential, tamper rejection and passphrase recovery. DMD 2.111.0 was exercised
physically; LDC was exercised physically with the locally available 1.42.0,
while CI covers the supported LDC 1.41.0 baseline. A second independent physical
authenticator was not available, so the optional two-key/removal scenarios
remain unexercised.

See [ADR 0008](docs/adr/0008-fido2-vault-key-protection.md).

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
