module app;

import credentials :
    CredentialHandle,
    CredentialNamespace,
    CredentialStatus,
    SecretBuffer;
import credentials.vault :
    EncryptedCredentialVault;

void useVault(
    string path,
    scope ref SecretBuffer passphrase
)
{
    auto ns = CredentialNamespace("org.example.credentials");

    EncryptedCredentialVault vault;

    auto status = EncryptedCredentialVault.openExisting(
        path,
        ns,
        vault
    );

    if (status == CredentialStatus.notFound)
    {
        status = EncryptedCredentialVault.createNew(
            path,
            ns,
            passphrase,
            vault
        );
    }
    else if (status == CredentialStatus.ok)
    {
        status = vault.unlock(passphrase);
    }

    if (status != CredentialStatus.ok)
        return;

    scope(exit) vault.lock();

    auto token = SecretBuffer(
        cast(const(ubyte)[]) "example-token"
    );

    CredentialHandle handle;
    if (vault.save(token, handle) != CredentialStatus.ok)
        return;

    vault.withSecret(
        handle,
        (scope const(ubyte)[] bytes) @safe
        {
            // Use the saved credential here.
        }
    );
}

void main()
{
    // Application code should obtain the passphrase from its own UI/input
    // flow. This literal exists only so the example is directly buildable.
    auto demoPassphrase = SecretBuffer(
        cast(const(ubyte)[]) "example-passphrase"
    );

    useVault("example-credentials.vault", demoPassphrase);
}
