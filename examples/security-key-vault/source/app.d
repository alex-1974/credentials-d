module app;

import credentials :
    CredentialStatus;
import credentials.security_key :
    SecurityKeyAccess,
    SecurityKeyInfo,
    addSecurityKeyUnlock,
    findSecurityKeys,
    unlockWithSecurityKey;
import credentials.vault :
    EncryptedCredentialVault,
    VaultUnlockMethod;

CredentialStatus addFirstConnectedKey(
    EncryptedCredentialVault vault,
    out VaultUnlockMethod method
)
{
    SecurityKeyInfo[] keys;
    auto status = findSecurityKeys(keys);

    if (status != CredentialStatus.ok)
        return status;

    if (keys.length == 0)
        return CredentialStatus.unavailable;

    return addSecurityKeyUnlock(
        vault,
        keys[0].id,
        SecurityKeyAccess.touch,
        method
    );
}

CredentialStatus unlockWithFirstConnectedKey(
    EncryptedCredentialVault vault,
    scope const VaultUnlockMethod method
)
{
    SecurityKeyInfo[] keys;
    auto status = findSecurityKeys(keys);

    if (status != CredentialStatus.ok)
        return status;

    if (keys.length == 0)
        return CredentialStatus.unavailable;

    return unlockWithSecurityKey(
        vault,
        keys[0].id,
        method
    );
}

void main()
{
    // The two functions above are intended to be called by an application's
    // vault setup/unlock workflow. No hardware is required just to build this
    // example.
}
