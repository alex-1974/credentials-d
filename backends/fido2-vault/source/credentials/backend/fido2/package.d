/**
 * Optional FIDO2 hmac-secret vault-key protector.
 */
module credentials.backend.fido2;

public import credentials.backend.fido2.binding :
    Fido2VaultBinding,
    Fido2VerificationPolicy,
    fido2ProtectorKind;

public import credentials.backend.fido2.protector :
    Fido2Capabilities,
    Fido2DeviceInfo,
    defaultFido2TimeoutMilliseconds,
    discoverFido2Devices,
    queryFido2Capabilities,
    enrollFido2VaultBinding,
    enrollFido2VaultBindingWithPin,
    enrollFido2VaultBindingWithUserVerification,
    withFido2WrappingKey,
    withFido2WrappingKeyUserVerification,
    withFido2WrappingKeyWithPin;

version (linux)
{
    public import credentials.backend.fido2.protector :
        addFido2TouchVaultUnlockWithEnrollmentPin,
        addFido2UserVerificationVaultUnlock,
        addFido2VaultUnlock,
        addFido2VaultUnlockWithPin,
        unlockVaultWithFido2,
        unlockVaultWithFido2Touch,
        unlockVaultWithFido2UserVerification,
        unlockVaultWithFido2WithPin;
}
