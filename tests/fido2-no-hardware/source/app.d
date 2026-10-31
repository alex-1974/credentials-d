module app;

import credentials : CredentialStatus;
import credentials.security_key :
    SecurityKeyCapabilities,
    SecurityKeyInfo,
    findSecurityKeys,
    getSecurityKeyCapabilities;

void main()
{
    SecurityKeyInfo[] keys;

    const status = findSecurityKeys(keys);
    assert(status == CredentialStatus.ok);

    foreach (const key; keys)
        assert(key.id.length != 0);

    SecurityKeyCapabilities capabilities;
    assert(
        getSecurityKeyCapabilities("", capabilities) ==
        CredentialStatus.invalidInput
    );
    assert(!capabilities.supportsVaultUnlock);
    assert(!capabilities.supportsSingleStepSetup);
}
