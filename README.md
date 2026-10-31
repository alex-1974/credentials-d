# credentials-d

Credential storage for D applications.

Use `credentials-d` when your application needs to keep passwords, API tokens,
refresh tokens or similar secrets out of ordinary configuration files.

The library gives you one small CRUD-style API and lets you choose where the
credential is stored:

| Platform / need | Use |
| --- | --- |
| Linux desktop | `LinuxCredentialStore` |
| Windows | `WindowsCredentialStore` |
| macOS | `MacOSCredentialStore` |
| Portable application-controlled file | `EncryptedCredentialVault` |
| Tests / temporary credentials | `MemoryCredentialStore` |

## Documentation

Consumer API documentation is published at:

https://alex-1974.github.io/credentials-d/

The site is generated from the public API on `main` and includes separate
documentation for the core library, platform stores, encrypted vault and
security-key support.

## Quick start

Every store belongs to an application namespace. Use one stable namespace for
the same credential domain across application runs.

```d
import credentials :
    CredentialHandle,
    CredentialNamespace,
    CredentialStatus,
    SecretBuffer;
import credentials.linux : LinuxCredentialStore;

auto ns = CredentialNamespace("org.example.application");
auto store = new LinuxCredentialStore(ns);
scope(exit) store.close();
```

### Save a credential

```d
auto token = SecretBuffer(
    cast(const(ubyte)[]) "my-api-token"
);

CredentialHandle handle;

if (store.save(token, handle) != CredentialStatus.ok)
{
    // Handle the storage error.
}
```

The returned `CredentialHandle` contains no credential plaintext. Persist its
serialized form in your normal application settings:

```d
settings.oauthTokenHandle = handle.serialize();
```

### Read it when needed

```d
CredentialHandle handle;

if (CredentialHandle.tryParse(settings.oauthTokenHandle, handle))
{
    const status = store.withSecret(
        handle,
        (scope const(ubyte)[] token) @safe
        {
            // Use token here, for example for one HTTP request.
        }
    );
}
```

The secret is available only inside the callback. Do the work that needs the
credential there rather than copying it into long-lived application state.

### Update it

```d
auto replacement = SecretBuffer(
    cast(const(ubyte)[]) "new-api-token"
);

const status = store.update(handle, replacement);
```

The handle remains the same.

### Remove it

```d
const status = store.remove(handle);
```

After a successful removal, discard the persisted handle from your settings as
well.

## Choosing a store

### Linux

Add the DUB subpackage:

```text
credentials-d:linux-secret-service
```

Use:

```d
import credentials : CredentialNamespace;
import credentials.linux : LinuxCredentialStore;

auto store = new LinuxCredentialStore(
    CredentialNamespace("org.example.application")
);
scope(exit) store.close();
```

Use this for ordinary Linux desktop applications when a system credential
service is available.

### Windows

Add:

```text
credentials-d:windows
```

Use:

```d
import credentials : CredentialNamespace;
import credentials.windows : WindowsCredentialStore;

auto store = new WindowsCredentialStore(
    CredentialNamespace("org.example.application")
);
```

Use this for credentials that should remain available to the current Windows
user across application runs.

### macOS

Add:

```text
credentials-d:macos-data-protection
```

Use:

```d
import credentials : CredentialNamespace;
import credentials.macos : MacOSCredentialStore;

auto store = new MacOSCredentialStore(
    CredentialNamespace("org.example.application")
);
```

The macOS backend is intended for signed/provisioned application builds. The
implementation is covered by CI, but final production qualification in such an
application context is still pending.

### Encrypted vault

Add:

```text
credentials-d:encrypted-vault
```

Use a vault when you deliberately want a portable, application-controlled
credential file instead of the operating-system credential store.

Create one:

```d
import credentials :
    CredentialNamespace,
    CredentialStatus,
    SecretBuffer;
import credentials.vault : EncryptedCredentialVault;

auto ns = CredentialNamespace("org.example.application");
auto passphrase = SecretBuffer(
    cast(const(ubyte)[]) "correct horse battery staple"
);

EncryptedCredentialVault vault;

assert(
    EncryptedCredentialVault.createNew(
        "credentials.vault",
        ns,
        passphrase,
        vault
    ) == CredentialStatus.ok
);

scope(exit) vault.lock();
```

Open an existing vault:

```d
EncryptedCredentialVault vault;

if (EncryptedCredentialVault.openExisting(
    "credentials.vault",
    ns,
    vault
) == CredentialStatus.ok)
{
    auto passphrase = SecretBuffer(
        cast(const(ubyte)[]) userEnteredPassphrase
    );

    if (vault.unlock(passphrase) == CredentialStatus.ok)
    {
        // save(), withSecret(), update() and remove() work here too.
    }
}
```

Call `lock()` when the application no longer needs access to the vault.

## Unlock a vault with a security key

Add:

```text
credentials-d:fido2-vault
```

First find the connected keys:

```d
import credentials : CredentialStatus;
import credentials.security_key :
    SecurityKeyInfo,
    findSecurityKeys;

SecurityKeyInfo[] keys;

if (findSecurityKeys(keys) == CredentialStatus.ok &&
    keys.length != 0)
{
    // Present keys to the user or select the expected device.
}
```

Add a key as an unlock method while the vault is already unlocked:

```d
import credentials.security_key :
    SecurityKeyAccess,
    addSecurityKeyUnlock;
import credentials.vault : VaultUnlockMethod;

VaultUnlockMethod unlockMethod;

const status = addSecurityKeyUnlock(
    vault,
    keys[0].id,
    SecurityKeyAccess.touch,
    unlockMethod
);
```

Persist the unlock method:

```d
settings.securityKeyUnlock = unlockMethod.serialize();
```

Later, open the vault and unlock it with the key:

```d
import credentials.security_key : unlockWithSecurityKey;

VaultUnlockMethod unlockMethod;

if (VaultUnlockMethod.tryParse(
    settings.securityKeyUnlock,
    unlockMethod
))
{
    const status = unlockWithSecurityKey(
        vault,
        keys[0].id,
        unlockMethod
    );
}
```

Use `SecurityKeyAccess.touch` when touching the key is enough. Use
`SecurityKeyAccess.verifiedUser` when the key must verify the user. If setup
or unlock requires a PIN, use the corresponding overload that accepts a
`SecretBuffer` PIN.

## Handling results

Normal operational outcomes are returned as `CredentialStatus`.

A typical application handles the few statuses relevant to its workflow:

```d
final switch (status)
{
    case CredentialStatus.ok:
        break;

    case CredentialStatus.notFound:
        // Ask the user to sign in again or recreate the credential.
        break;

    case CredentialStatus.locked:
        // Unlock the vault first.
        break;

    case CredentialStatus.userCancelled:
        // Keep the current UI state; the user chose not to continue.
        break;

    case CredentialStatus.unavailable:
        // The selected credential store or security key is not available.
        break;

    default:
        // Report or log the remaining error for this workflow.
        break;
}
```

See the generated API documentation for the meaning of every status.

## Store capabilities

If your application can work with more than one store, inspect
`store.capabilities` instead of assuming behavior from the platform name.

For example:

```d
const caps = store.capabilities;

if (caps.blocking == StoreBlocking.mayPrompt)
{
    // Run the operation away from the render/UI thread.
}
```

Capabilities also tell you whether storage is persistent, where it can move,
who controls unlocking and what concurrency contract the store provides.

## Persisted values

These values are designed to be stored in normal application settings:

- `CredentialNamespace.serialize()`
- `CredentialHandle.serialize()`
- `VaultUnlockMethod.serialize()`

Parse persisted values with their matching `tryParse()` function.

Do not interpret their serialized contents. Treat them as opaque values owned by
credentials-d.

## Complete examples

The repository contains small buildable examples that use only the supported
consumer API:

- [basic store](examples/basic-store/source/app.d)
- [encrypted vault](examples/encrypted-vault/source/app.d)
- [security-key vault unlock](examples/security-key-vault/source/app.d)

They are also built by CI, so the examples stay in sync with the public API.

## API stability

The intended public surface is documented in
[`docs/API_STABILITY.md`](docs/API_STABILITY.md).

Consumer code should import:

- `credentials`
- `credentials.linux`
- `credentials.windows`
- `credentials.macos`
- `credentials.vault`
- `credentials.security_key`

Modules under `credentials.backend.*` are implementation modules and are not
part of the public compatibility contract.

## Release status

`v0.1.0` is the first public API release.

Linux, Windows, encrypted-vault and the tested security-key workflows have
qualification coverage. The macOS backend still needs final qualification in a
properly signed/provisioned macOS application.

For security design, qualification evidence and implementation rationale, see
the documents under `docs/security/` and `docs/adr/`.

## Supported compilers

Development baseline:

```text
DMD 2.111.0
LDC 1.41.0
```

## Development

```bash
dub test --compiler=dmd --force
dub test --compiler=ldc2 --force
dub run --root=tests/consumer --compiler=dmd --force
```

Normal integration targets `develop`. `main` is reserved for release state.

## License

MIT.
