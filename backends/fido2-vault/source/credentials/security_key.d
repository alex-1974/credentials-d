/**
 * Use a physical security key to unlock an encrypted credential vault.
 *
 * Typical flow:
 *
 * 1. findSecurityKeys() to show or select a connected key;
 * 2. while the vault is unlocked, call addSecurityKeyUnlock();
 * 3. persist the returned VaultUnlockMethod;
 * 4. later open the vault and call unlockWithSecurityKey().
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
 * Show manufacturer/product to the user when choosing between several keys.
 * Pass id back to the functions in this module during the current connection.
 */
struct SecurityKeyInfo
{
    /** Runtime id used with the functions in this module. */
    string id;

    /** Human-readable manufacturer text reported by the device, if available. */
    string manufacturer;

    /** Human-readable product text reported by the device, if available. */
    string product;
}

/**
 * Features that can affect setup or the user experience for one security key.
 *
 * Use this when the UI needs to explain available unlock choices before setup.
 */
struct SecurityKeyCapabilities
{
    /** Whether this key can be used to unlock a credentials-d vault. */
    bool supportsVaultUnlock;

    /** Whether setup usually needs only one interaction with the key. */
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
 * How the user should prove presence or identity when using the key.
 */
enum SecurityKeyAccess
{
    /** Physical presence/touch is sufficient during normal unlock. */
    touch,

    /** The key must verify the user, for example by fingerprint or PIN. */
    verifiedUser
}

/**
 * Find the security keys currently available to the application.
 *
 * Use this before setup or unlock to let the user choose a connected key.
 *
 * Params:
 *     keys = Receives the connected keys.
 *
 * Returns:
 *     ok when discovery succeeded. An empty array means no key is connected.
 *
 * Examples:
 * ---
 * SecurityKeyInfo[] keys;
 *
 * if (findSecurityKeys(keys) == CredentialStatus.ok)
 * {
 *     foreach (key; keys)
 *         showKeyChoice(key.manufacturer, key.product);
 * }
 * ---
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
 * Check which vault-unlock features one connected key offers.
 *
 * Use this when the setup UI should explain whether the key supports a PIN,
 * built-in verification or a shorter setup flow.
 *
 * Params:
 *     keyId = id returned by findSecurityKeys().
 *     capabilities = Receives the available features.
 *
 * Returns:
 *     ok when the capabilities were read.
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
     * Add a connected security key as a way to unlock this vault.
     *
     * Call this while vault is already unlocked. Persist method.serialize() on
     * success so it can be used during a later application run.
     *
     * Params:
     *     vault = Currently unlocked vault.
     *     keyId = id returned by findSecurityKeys().
     *     access = Whether touch is enough or the user must be verified.
     *     method = Receives the unlock method to persist.
     *
     * Returns:
     *     ok on success. userActionRequired means setup needs the overload that
     *     accepts a PIN.
     *
     * Examples:
     * ---
     * VaultUnlockMethod method;
     *
     * auto status = addSecurityKeyUnlock(
     *     vault,
     *     key.id,
     *     SecurityKeyAccess.touch,
     *     method
     * );
     *
     * if (status == CredentialStatus.ok)
     *     settings.securityKeyUnlock = method.serialize();
     * ---
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
     * Add a security key when setup requires its PIN.
     *
     * Use this overload after the no-PIN version returns userActionRequired, or
     * when verifiedUser is intentionally PIN-backed.
     *
     * Params:
     *     vault = Currently unlocked vault.
     *     keyId = id returned by findSecurityKeys().
     *     access = Required user interaction.
     *     pin = PIN entered by the user.
     *     method = Receives the unlock method to persist.
     *
     * Returns:
     *     ok on success.
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
     * Unlock an opened vault with a connected security key.
     *
     * Restore method from application settings with VaultUnlockMethod.tryParse()
     * and find the connected key with findSecurityKeys() first.
     *
     * Params:
     *     vault = Locked vault returned by openExisting().
     *     keyId = id of the connected key.
     *     method = Previously saved unlock method.
     *
     * Returns:
     *     ok when the vault is ready for normal CredentialStore operations.
     *
     * Examples:
     * ---
     * auto status = unlockWithSecurityKey(
     *     vault,
     *     key.id,
     *     unlockMethod
     * );
     * ---
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
     * Unlock a vault with a security key and PIN.
     *
     * Use this overload when the saved unlock method requires PIN-backed user
     * verification.
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
