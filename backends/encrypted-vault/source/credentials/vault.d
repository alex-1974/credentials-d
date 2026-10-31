/**
 * Portable encrypted credential storage.
 *
 * Use this module when your application deliberately wants to keep credentials
 * in its own portable vault file instead of an operating-system credential
 * store.
 *
 * Examples:
 * ---
 * auto ns = CredentialNamespace("org.example.application");
 * auto passphrase = SecretBuffer(passphraseBytes);
 *
 * EncryptedCredentialVault vault;
 * auto status = EncryptedCredentialVault.createNew(
 *     "credentials.vault",
 *     ns,
 *     passphrase,
 *     vault
 * );
 * ---
 */
module credentials.vault;

public import credentials.backend.vault.protector :
    VaultUnlockMethod;

version (linux)
{
    public import credentials.backend.vault.posix_store :
        EncryptedCredentialVault;
}
