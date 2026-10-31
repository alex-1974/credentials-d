/**
 * Public security-key support for encrypted credential vaults.
 *
 * FIDO2, CTAP, credential bindings, hmac-secret, COSE algorithms and native
 * device paths are implementation details of this backend.
 */
module credentials.security_key;

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
    import credentials.vault :
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
    /** Opaque runtime selector passed back to security-key operations. */
    string id;

    /** Human-readable manufacturer text reported by the device, if available. */
    string manufacturer;

    /** Human-readable product text reported by the device, if available. */
    string product;
}

/**
 * Consumer-relevant capabilities of one security key.
 *
 * Protocol extensions and signing algorithms are deliberately not exposed.
 */
struct SecurityKeyCapabilities
{
    /** Whether this key can protect credentials-d vault unlock material. */
    bool supportsVaultUnlock;

    /** Whether setup can combine credential creation and key derivation. */
    bool supportsSingleStepSetup;

    /** Whether the key supports PIN-based verification. */
    bool supportsPin;

    /** Whether a PIN is currently configured on the key. */
    bool pinConfigured;

    /** Whether the key supports built-in verification such as fingerprint. */
    bool supportsBuiltInVerification;

    /** Whether built-in verification is currently configured and usable. */
    bool builtInVerificationConfigured;
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
 *
 * Params:
 *     keys = Receives one runtime descriptor per discovered key.
 *
 * Returns:
 *     CredentialStatus.ok on successful discovery. An empty result with ok
 *     means no supported key is currently connected.
 *
 * Note:
 *     SecurityKeyInfo.id is a runtime selector and must not be persisted as a
 *     durable identity.
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
 * Read consumer-relevant capabilities for one connected security key.
 *
 * No touch, PIN, credential creation or secret derivation is performed.
 *
 * Params:
 *     keyId = Opaque runtime id returned by findSecurityKeys().
 *     capabilities = Receives the capability snapshot on success.
 *
 * Returns:
 *     CredentialStatus.ok on success, otherwise the discovery/backend outcome.
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
    capabilities.supportsBuiltInVerification =
        native.builtInUserVerificationSupported;
    capabilities.builtInVerificationConfigured =
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
     * scope. Consumers do not need to supply protocol-specific identifiers.
     *
     * Params:
     *     vault = Currently unlocked vault to protect.
     *     keyId = Runtime id returned by findSecurityKeys().
     *     access = Required interaction/verification policy.
     *     method = Receives persistable non-secret unlock metadata on success.
     *
     * Returns:
     *     CredentialStatus.ok on success. userActionRequired means setup needs
     *     an explicit action that this overload cannot provide, such as a PIN.
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
     * Use this overload when setup requires PIN authorization or when
     * SecurityKeyAccess.verifiedUser is PIN-backed.
     *
     * Params:
     *     vault = Currently unlocked vault to protect.
     *     keyId = Runtime id returned by findSecurityKeys().
     *     access = Required interaction/verification policy.
     *     pin = Secret PIN buffer; it is not persisted by credentials-d.
     *     method = Receives persistable non-secret unlock metadata on success.
     *
     * Returns:
     *     CredentialStatus.ok on success, otherwise the hardware/backend
     *     outcome.
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
     * Touch methods require physical presence. verifiedUser methods may be
     * satisfied by built-in verification such as fingerprint.
     *
     * Params:
     *     vault = Locked vault instance opened from disk.
     *     keyId = Runtime id of the connected key.
     *     method = Persisted non-secret unlock method created earlier.
     *
     * Returns:
     *     CredentialStatus.ok when the vault was unlocked.
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
