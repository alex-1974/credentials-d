/**
 * Consumer-facing security-key support for encrypted credential vaults.
 *
 * FIDO2, CTAP, credential bindings, hmac-secret, COSE algorithms and native
 * device paths are implementation details of this backend.
 */
module credentials.backend.fido2;

import credentials.backend.fido2.binding :
    Fido2VerificationPolicy;
import credentials.backend.fido2.protector :
    Fido2Capabilities,
    Fido2DeviceInfo,
    addFido2VaultUnlock,
    addFido2VaultUnlockWithPin,
    discoverFido2Devices,
    queryFido2Capabilities,
    unlockVaultWithFido2,
    unlockVaultWithFido2WithPin;
import credentials.secret : SecretBuffer;
import credentials.store : CredentialStatus;

version (linux)
{
    import credentials.backend.vault :
        EncryptedCredentialVault,
        VaultUnlockMethod;
}

/**
 * One currently connected security key.
 *
 * id is an opaque runtime selector. It may change after reconnect or reboot
 * and must not be persisted as the identity of an unlock method.
 */
struct SecurityKeyInfo
{
    string id;
    string manufacturer;
    string product;
}

/**
 * Consumer-relevant capabilities of one security key.
 *
 * Protocol extensions and signing algorithms are deliberately not exposed.
 */
struct SecurityKeyCapabilities
{
    bool supportsVaultUnlock;
    bool supportsSingleStepSetup;
    bool supportsPin;
    bool pinConfigured;
    bool supportsBuiltInUserVerification;
    bool builtInUserVerificationConfigured;
}

/**
 * User interaction required when using a security key.
 */
enum SecurityKeyAccess
{
    /** Physical presence/touch is sufficient during normal unlock. */
    touch,

    /** The key must verify the user, for example by fingerprint or PIN. */
    verifiedUser
}

/**
 * Find currently connected security keys.
 */
CredentialStatus findSecurityKeys(
    out SecurityKeyInfo[] keys
) @safe
{
    Fido2DeviceInfo[] devices;
    const status = discoverFido2Devices(devices);
    if (status != CredentialStatus.ok)
    {
        keys = null;
        return status;
    }

    keys = new SecurityKeyInfo[devices.length];
    foreach (i, ref const device; devices)
    {
        keys[i] = SecurityKeyInfo(
            device.path,
            device.manufacturer,
            device.product
        );
    }

    return CredentialStatus.ok;
}

/**
 * Read the capabilities relevant to credentials-d consumers.
 *
 * No touch, PIN, credential creation or secret derivation is performed.
 */
CredentialStatus getSecurityKeyCapabilities(
    string keyId,
    out SecurityKeyCapabilities capabilities
) @safe
{
    capabilities = SecurityKeyCapabilities.init;

    Fido2Capabilities native;
    const status = queryFido2Capabilities(keyId, native);
    if (status != CredentialStatus.ok)
        return status;

    capabilities.supportsVaultUnlock = native.hmacSecret;
    capabilities.supportsSingleStepSetup =
        native.hmacSecretMakeCredentialUsable;
    capabilities.supportsPin = native.clientPinSupported;
    capabilities.pinConfigured = native.clientPinConfigured;
    capabilities.supportsBuiltInUserVerification =
        native.builtInUserVerificationSupported;
    capabilities.builtInUserVerificationConfigured =
        native.builtInUserVerificationConfigured;

    return CredentialStatus.ok;
}

private Fido2VerificationPolicy nativePolicy(
    SecurityKeyAccess access
) @nogc nothrow pure @safe
{
    final switch (access)
    {
        case SecurityKeyAccess.touch:
            return Fido2VerificationPolicy.touchOnly;

        case SecurityKeyAccess.verifiedUser:
            return Fido2VerificationPolicy.userVerificationRequired;
    }
}

version (linux)
{
    /**
     * Add a security-key unlock method to an already unlocked vault.
     *
     * The vault's CredentialNamespace is used as the security-key application
     * scope. Consumers do not need to supply protocol-specific RP identifiers.
     */
    CredentialStatus addSecurityKeyUnlock(
        EncryptedCredentialVault vault,
        string keyId,
        SecurityKeyAccess access,
        out VaultUnlockMethod method
    ) @safe
    {
        method = VaultUnlockMethod.init;

        if (vault is null)
            return CredentialStatus.invalidInput;

        return addFido2VaultUnlock(
            vault,
            keyId,
            vault.credentialNamespace.serialize(),
            nativePolicy(access),
            method
        );
    }

    /**
     * Add a security-key unlock method while supplying a PIN.
     *
     * This overload is useful when the authenticator requires PIN
     * authorization during setup or when verified-user access is PIN-backed.
     */
    CredentialStatus addSecurityKeyUnlock(
        EncryptedCredentialVault vault,
        string keyId,
        SecurityKeyAccess access,
        scope ref const SecretBuffer pin,
        out VaultUnlockMethod method
    ) @safe
    {
        method = VaultUnlockMethod.init;

        if (vault is null)
            return CredentialStatus.invalidInput;

        return addFido2VaultUnlockWithPin(
            vault,
            keyId,
            vault.credentialNamespace.serialize(),
            nativePolicy(access),
            pin,
            method
        );
    }

    /**
     * Unlock a vault with a security key.
     *
     * Touch-only methods require physical presence. verifiedUser methods may
     * be satisfied by built-in verification such as fingerprint.
     */
    CredentialStatus unlockWithSecurityKey(
        EncryptedCredentialVault vault,
        string keyId,
        scope const VaultUnlockMethod method
    ) @safe
    {
        if (vault is null)
            return CredentialStatus.invalidInput;

        return unlockVaultWithFido2(
            vault,
            keyId,
            method
        );
    }

    /**
     * Unlock a verified-user security-key method using a PIN.
     */
    CredentialStatus unlockWithSecurityKey(
        EncryptedCredentialVault vault,
        string keyId,
        scope const VaultUnlockMethod method,
        scope ref const SecretBuffer pin
    ) @safe
    {
        if (vault is null)
            return CredentialStatus.invalidInput;

        return unlockVaultWithFido2WithPin(
            vault,
            keyId,
            method,
            pin
        );
    }
}
