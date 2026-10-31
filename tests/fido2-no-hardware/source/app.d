module app;

import credentials : CredentialStatus;
import credentials.security_key :
    SecurityKeyAccess,
    SecurityKeyCapabilities,
    SecurityKeyInfo,
    addSecurityKeyUnlock,
    findSecurityKeys,
    getSecurityKeyCapabilities,
    unlockWithSecurityKey;
import credentials.vault :
    EncryptedCredentialVault,
    VaultUnlockMethod;

void main()
{
    SecurityKeyInfo[] keys;

    const status = findSecurityKeys(keys);
    assert(status == CredentialStatus.ok);

    foreach (const key; keys)
        assert(key.id.length != 0);

    static assert(__traits(compiles,
    {
        EncryptedCredentialVault vault;
        VaultUnlockMethod method;

        addSecurityKeyUnlock(
            vault,
            "runtime-key-id",
            SecurityKeyAccess.touch,
            method
        );

        unlockWithSecurityKey(
            vault,
            "runtime-key-id",
            method
        );
    }));

    SecurityKeyCapabilities capabilities;
    assert(
        getSecurityKeyCapabilities("", capabilities) ==
        CredentialStatus.invalidInput
    );
    assert(!capabilities.supportsVaultUnlock);
    assert(!capabilities.supportsSingleStepSetup);
}
