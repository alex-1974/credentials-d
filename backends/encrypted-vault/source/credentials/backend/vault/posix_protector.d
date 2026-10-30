/**
 * POSIX persistent-vault adapter for external key-protector envelopes.
 */
module credentials.backend.vault.posix_protector;

version (linux):

import credentials.backend.vault.posix_store :
    EncryptedVaultCredentialStore;
import credentials.backend.vault.protector :
    VaultUnlockEnvelope,
    VaultWrappingKeySource,
    createVaultUnlockEnvelope,
    recoverVaultKeyFromEnvelope;
import credentials.backend.vault.sodium :
    vaultKeyBytes,
    zeroFixed;
import credentials.store : CredentialStatus;

/**
 * Create an external protector envelope for the currently unlocked store.
 *
 * One ephemeral stack copy of the vault key is made while the store is locked,
 * then zeroized after wrapping.
 */
CredentialStatus createVaultUnlockEnvelopeForStore(
    EncryptedVaultCredentialStore store,
    string protectorKind,
    scope const(ubyte)[] protectorBinding,
    scope VaultWrappingKeySource keySource,
    out VaultUnlockEnvelope envelope
) @safe
{
    envelope = VaultUnlockEnvelope.init;

    if (store is null)
        return CredentialStatus.invalidInput;

    ubyte[16] vaultId;
    ubyte[vaultKeyBytes] vaultKey;
    scope(exit) zeroFixed(vaultKey);

    auto status = store.copyUnlockMaterial(vaultId, vaultKey);
    if (status != CredentialStatus.ok)
        return status;

    return createVaultUnlockEnvelope(
        store.credentialNamespace,
        vaultId,
        vaultKey[],
        protectorKind,
        protectorBinding,
        keySource,
        envelope
    );
}

/**
 * Unlock a persistent vault through an external protector envelope.
 */
CredentialStatus unlockVaultWithEnvelope(
    EncryptedVaultCredentialStore store,
    scope const VaultUnlockEnvelope envelope,
    scope VaultWrappingKeySource keySource
) @safe
{
    if (store is null)
        return CredentialStatus.invalidInput;

    ubyte[16] vaultId;
    auto status = store.currentVaultId(vaultId);
    if (status != CredentialStatus.ok)
        return status;

    return recoverVaultKeyFromEnvelope(
        store.credentialNamespace,
        vaultId,
        envelope,
        keySource,
        (scope const(ubyte)[] recoveredKey) @safe
        {
            return store.unlockWithVaultKey(recoveredKey);
        }
    );
}
