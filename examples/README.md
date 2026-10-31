# Consumer examples

These examples use only the supported public API.

- `basic-store`: save, restore, read, update and remove a credential.
- `encrypted-vault`: create/open a portable vault and use the normal
  CredentialStore operations.
- `security-key-vault`: add a connected security key as a vault unlock method
  and use it again later.

Build an example from the repository root:

```bash
dub build --root=examples/basic-store
dub build --root=examples/encrypted-vault
dub build --root=examples/security-key-vault
```

The vault and security-key examples need the same native libraries as their
respective credentials-d subpackages.
