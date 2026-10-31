/**
 * Public encrypted credential vault API.
 *
 * Cryptographic image handling, wrapping-key derivation, protector envelopes
 * and filesystem mechanics are implementation details and are deliberately
 * not re-exported from this package.
 */
module credentials.vault;

public import credentials.backend.vault.protector :
    VaultUnlockMethod;

version (linux)
{
    public import credentials.backend.vault.posix_store :
        EncryptedCredentialVault;
}
