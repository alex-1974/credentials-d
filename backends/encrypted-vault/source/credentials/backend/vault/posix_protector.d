/**
 * POSIX persistent-vault adapter for external key-protector envelopes.
 */
module credentials.backend.vault.posix_protector;

version (linux):

import credentials.backend.vault.posix_store :
    EncryptedCredentialVault;
import credentials.backend.vault.protector :
    VaultUnlockMethod,
    VaultWrappingKeySource,
    createVaultUnlockMethod,
    createVaultUnlockMethodWithSalt,
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
CredentialStatus createVaultUnlockMethodForStore(
    EncryptedCredentialVault store,
    string protectorKind,
    scope const(ubyte)[] protectorBinding,
    scope VaultWrappingKeySource keySource,
    out VaultUnlockMethod envelope
) @safe
{
    envelope = VaultUnlockMethod.init;

    if (store is null)
        return CredentialStatus.invalidInput;

    ubyte[16] vaultId;
    ubyte[vaultKeyBytes] vaultKey;
    scope(exit) zeroFixed(vaultKey);

    auto status = store.copyUnlockMaterial(vaultId, vaultKey);
    if (status != CredentialStatus.ok)
        return status;

    return createVaultUnlockMethod(
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
 * Internal sibling-backend variant for protectors that already selected the
 * envelope salt before deriving their wrapping key.
 */
package(credentials.backend) CredentialStatus createVaultUnlockMethodForStoreWithSalt(
    EncryptedCredentialVault store,
    string protectorKind,
    scope const(ubyte)[] protectorBinding,
    scope const ubyte[32] salt,
    scope VaultWrappingKeySource keySource,
    out VaultUnlockMethod envelope
) @safe
{
    envelope = VaultUnlockMethod.init;

    if (store is null)
        return CredentialStatus.invalidInput;

    ubyte[16] vaultId;
    ubyte[vaultKeyBytes] vaultKey;
    scope(exit) zeroFixed(vaultKey);

    auto status = store.copyUnlockMaterial(vaultId, vaultKey);
    if (status != CredentialStatus.ok)
        return status;

    return createVaultUnlockMethodWithSalt(
        store.credentialNamespace,
        vaultId,
        vaultKey[],
        protectorKind,
        protectorBinding,
        salt,
        keySource,
        envelope
    );
}

/**
 * Unlock a persistent vault through an external protector envelope.
 */
CredentialStatus unlockVaultWithEnvelope(
    EncryptedCredentialVault store,
    scope const VaultUnlockMethod envelope,
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
