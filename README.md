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
assert(store.save(secret, handle) == CredentialStatus.ok);

assert(store.withSecret(handle, (scope const(ubyte)[] bytes) @safe
{
    // Use plaintext only inside this explicit callback.
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


## Security-key vault unlock

Hardware-assisted vault unlock is available through the optional:

```text
credentials-d:fido2-vault
```

The public API deliberately speaks in security-key terms. Consumers do not need
to understand FIDO2/CTAP commands, hmac-secret extensions, credential
protection flags, COSE algorithms, or authenticator device-path semantics.

Connected keys can be discovered and inspected without user interaction:

```d
import credentials.backend.fido2 :
    SecurityKeyCapabilities,
    SecurityKeyInfo,
    findSecurityKeys,
    getSecurityKeyCapabilities;

SecurityKeyInfo[] keys;
assert(findSecurityKeys(keys) == CredentialStatus.ok);

SecurityKeyCapabilities capabilities;
assert(getSecurityKeyCapabilities(
    keys[0].id,
    capabilities
) == CredentialStatus.ok);
```

The consumer-relevant capabilities describe whether the key can unlock a vault,
whether setup can be completed in a single key interaction, and whether PIN or
built-in user verification is available. Protocol extensions and signing
algorithms remain internal diagnostics.

A vault unlock method is added with one of two clear interaction policies:

```d
import credentials.backend.fido2 :
    SecurityKeyAccess,
    addSecurityKeyUnlock,
    unlockWithSecurityKey;
import credentials.backend.vault :
    EncryptedCredentialVault,
    VaultUnlockMethod;

VaultUnlockMethod unlockMethod;

auto status = addSecurityKeyUnlock(
    vault,
    keys[0].id,
    SecurityKeyAccess.touch,
    unlockMethod
);

// Later, after reopening the locked vault:
status = unlockWithSecurityKey(
    vault,
    keys[0].id,
    unlockMethod
);
```

`SecurityKeyAccess.touch` means that normal unlock requires physical
presence/touch. `SecurityKeyAccess.verifiedUser` means that the key must verify
the user; the key may satisfy that requirement through built-in verification
such as fingerprint, or through a PIN-backed flow. A PIN overload is available
when setup or verified-user access requires one.

The vault's `CredentialNamespace` is used internally as the security-key
application scope. Consumers do not supply protocol-specific relying-party
identifiers.

Internally, the backend uses FIDO2 hmac-secret to derive a credential-scoped
wrapping key. CTAP 2.2 hmac-secret-mc is used automatically as a single-step
setup fast path when both the authenticator and local libfido2 support it.
Older authenticators transparently retain the qualified two-step setup path.
These implementation choices do not change the public unlock-method format.

The physical security-key contract was qualified on 2026-10-31 with a YubiKey
5.2.4 for touch-only operation, PIN-backed user verification, wrong credential,
tamper rejection and passphrase recovery. Built-in biometric verification and
the CTAP 2.2 single-step fast path are implemented but require suitable hardware
for positive physical qualification.

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
