/**
 * Encrypted-vault backend internals.
 *
 * The public CredentialStore backend is added after the cryptographic format
 * core is qualified.
 */
module credentials.backend.vault;

public import credentials.backend.vault.core :
    VaultCoreStatus,
    createEmptyVaultImage,
    vaultAcquire,
    vaultPut,
    vaultRemove,
    vaultReplace;
