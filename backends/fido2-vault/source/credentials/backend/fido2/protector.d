/**
 * FIDO2 hmac-secret vault-key protector.
 */
module credentials.backend.fido2.protector;

import core.exception : onOutOfMemoryError;
import core.stdc.stdlib : free, malloc;
import core.volatile : volatileStore;
version (Posix)
{
    import core.sys.posix.dlfcn : RTLD_LAZY, dlclose, dlopen, dlsym;
}
import credentials.backend.fido2.binding :
    Fido2VaultBinding,
    Fido2VerificationPolicy,
    fido2ProtectorKind,
    maximumCredentialIdBytes,
    validRpId;
import credentials.backend.fido2.ffi;
import credentials.backend.vault.protector :
    VaultUnlockMethod,
    VaultWrappingKeySource,
    protectorSaltBytes;
import credentials.namespace : CredentialNamespace;
import credentials.random : secureRandomBytes;
import credentials.secret : SecretBuffer;
import credentials.store :
    CredentialStatus,
    SecretCallback;
import std.string : fromStringz, toStringz;

version (linux)
{
    import credentials.backend.vault.posix_protector :
        createVaultUnlockMethodForStore,
        createVaultUnlockMethodForStoreWithSalt,
        unlockVaultWithEnvelope;
    import credentials.backend.vault.posix_store :
        EncryptedCredentialVault;
}

enum int defaultFido2TimeoutMilliseconds = 30_000;
enum size_t maximumFido2Devices = 64;
private enum string compatibilityUserName = "credentials-d";

/**
 * Non-secret runtime discovery metadata.
 *
 * Device paths are runtime selectors only and are never persisted in
 * Fido2VaultBinding.
 */
struct Fido2DeviceInfo
{
    string path;
    string manufacturer;
    string product;
}

/**
 * Non-secret capabilities reported by CTAP authenticatorGetInfo.
 *
 * Capability discovery is advisory: consumers should use it to choose UX or
 * optional fast paths, while security-sensitive operations still fail closed
 * if the authenticator cannot satisfy the requested policy.
 *
 * remainingDiscoverableCredentials is -1 when the authenticator does not
 * advertise the CTAP 2.1 estimate. uvModality is the raw FIDO Registry bitmask
 * and is zero when not advertised.
 */
struct Fido2Capabilities
{
    bool hmacSecret;
    bool hmacSecretMakeCredential;
    bool hmacSecretMakeCredentialUsable;
    bool credProtect;

    bool clientPinSupported;
    bool clientPinConfigured;

    bool builtInUserVerificationSupported;
    bool builtInUserVerificationConfigured;
    ulong uvModality;

    bool discoverableCredentialsSupported;
    long remainingDiscoverableCredentials = -1;

    bool es256;
    bool edDsa;
    bool es384;
    bool rs256;

    ulong firmwareVersion;
}

/**
 * Query one currently connected authenticator's standard FIDO2 capabilities.
 *
 * No PIN, touch, credential creation or secret derivation is performed.
 * devicePath is a runtime selector and is not persisted.
 */
CredentialStatus queryFido2Capabilities(
    string devicePath,
    out Fido2Capabilities capabilities
) @trusted
{
    capabilities = Fido2Capabilities.init;

    if (!validDevicePath(devicePath))
        return CredentialStatus.invalidInput;

    fido_init(FIDO_DISABLE_U2F_FALLBACK);

    auto dev = fido_dev_new();
    if (dev is null)
        return CredentialStatus.backendFailure;

    scope(exit)
    {
        fido_dev_close(dev);
        fido_dev_free(&dev);
    }

    int rc = fido_dev_open(
        dev,
        cast(const(char)*)toStringz(devicePath)
    );
    if (rc != FIDO_OK)
        return mapFidoStatus(rc);

    rc = fido_dev_set_timeout(
        dev,
        defaultFido2TimeoutMilliseconds
    );
    if (rc != FIDO_OK)
        return mapFidoStatus(rc);

    auto info = fido_cbor_info_new();
    if (info is null)
        return CredentialStatus.backendFailure;

    scope(exit) fido_cbor_info_free(&info);

    rc = fido_dev_get_cbor_info(dev, info);
    if (rc != FIDO_OK)
        return mapFidoStatus(rc);

    capabilities.hmacSecret =
        hasCborString(
            fido_cbor_info_extensions_ptr(info),
            fido_cbor_info_extensions_len(info),
            "hmac-secret"
        );
    capabilities.hmacSecretMakeCredential =
        hasCborString(
            fido_cbor_info_extensions_ptr(info),
            fido_cbor_info_extensions_len(info),
            "hmac-secret-mc"
        );
    capabilities.hmacSecretMakeCredentialUsable =
        capabilities.hmacSecretMakeCredential &&
        hmacSecretMcAbiAvailable();
    capabilities.credProtect =
        hasCborString(
            fido_cbor_info_extensions_ptr(info),
            fido_cbor_info_extensions_len(info),
            "credProtect"
        );

    bool optionValue;
    capabilities.clientPinSupported =
        findCborOption(info, "clientPin", optionValue);
    capabilities.clientPinConfigured =
        capabilities.clientPinSupported && optionValue;

    optionValue = false;
    capabilities.builtInUserVerificationSupported =
        findCborOption(info, "uv", optionValue);
    capabilities.builtInUserVerificationConfigured =
        capabilities.builtInUserVerificationSupported && optionValue;

    optionValue = false;
    capabilities.discoverableCredentialsSupported =
        findCborOption(info, "rk", optionValue) && optionValue;

    const algorithmCount =
        fido_cbor_info_algorithm_count(info);
    foreach (i; 0 .. algorithmCount)
    {
        switch (fido_cbor_info_algorithm_cose(info, i))
        {
            case COSE_ES256:
                capabilities.es256 = true;
                break;
            case COSE_EDDSA:
                capabilities.edDsa = true;
                break;
            case COSE_ES384:
                capabilities.es384 = true;
                break;
            case COSE_RS256:
                capabilities.rs256 = true;
                break;
            default:
                break;
        }
    }

    capabilities.firmwareVersion =
        fido_cbor_info_fwversion(info);
    capabilities.uvModality =
        fido_cbor_info_uv_modality(info);
    capabilities.remainingDiscoverableCredentials =
        fido_cbor_info_rk_remaining(info);

    return CredentialStatus.ok;
}

/**
 * Discover currently available libfido2 devices.
 *
 * An empty list with status ok means no discoverable device is currently
 * attached.
 */
CredentialStatus discoverFido2Devices(
    out Fido2DeviceInfo[] devices
) @trusted
{
    devices = null;

    fido_init(FIDO_DISABLE_U2F_FALLBACK);

    auto list = fido_dev_info_new(maximumFido2Devices);
    if (list is null)
        return CredentialStatus.backendFailure;

    scope(exit) fido_dev_info_free(&list, maximumFido2Devices);

    size_t count;
    const rc =
        fido_dev_info_manifest(
            list,
            maximumFido2Devices,
            &count
        );

    if (rc != FIDO_OK)
        return mapFidoStatus(rc);

    if (count > maximumFido2Devices)
        return CredentialStatus.backendFailure;

    devices = new Fido2DeviceInfo[count];

    foreach (i; 0 .. count)
    {
        const info = fido_dev_info_ptr(list, i);
        if (info is null)
            return CredentialStatus.backendFailure;

        devices[i].path = copyCString(fido_dev_info_path(info));
        devices[i].manufacturer =
            copyCString(fido_dev_info_manufacturer_string(info));
        devices[i].product =
            copyCString(fido_dev_info_product_string(info));

        if (devices[i].path.length == 0)
            return CredentialStatus.backendFailure;
    }

    return CredentialStatus.ok;
}

/**
 * Enroll a non-resident FIDO2 credential with hmac-secret enabled.
 *
 * For userVerificationRequired, credProtect=UV_REQUIRED and UV are requested.
 * Unsupported protection is an error rather than a silent downgrade.
 */
CredentialStatus enrollFido2VaultBinding(
    string devicePath,
    string rpId,
    Fido2VerificationPolicy policy,
    out Fido2VaultBinding binding
) @safe
{
    return enrollImpl(
        devicePath,
        rpId,
        policy,
        null,
        null,
        null,
        binding
    );
}

/**
 * Enroll with an explicit PIN supplied through SecretBuffer.
 *
 * Some PIN-protected CTAP2.0 authenticators require PIN authorization for
 * MakeCredential even when the resulting binding intentionally uses the
 * user-presence-only hmac-secret branch for later assertions. In that case the
 * PIN authorizes credential creation only; the persisted verification policy
 * remains userPresence and later key derivation still occurs without PIN/UV.
 *
 * For userVerificationRequired, the PIN additionally satisfies the requested
 * UV/credProtect policy.
 */
/**
 * Enroll a user-verification-required binding without supplying a PIN.
 *
 * This path is intended for authenticators that can satisfy UV internally,
 * such as biometric authenticators. The authenticator decides the UV modality;
 * credentials-d only requires the resulting assertion policy.
 */
CredentialStatus enrollFido2VaultBindingWithUserVerification(
    string devicePath,
    string rpId,
    out Fido2VaultBinding binding
) @safe
{
    return enrollFido2VaultBinding(
        devicePath,
        rpId,
        Fido2VerificationPolicy.userVerificationRequired,
        binding
    );
}

CredentialStatus enrollFido2VaultBindingWithPin(
    string devicePath,
    string rpId,
    Fido2VerificationPolicy policy,
    scope ref const SecretBuffer pin,
    out Fido2VaultBinding binding
) @safe
{
    binding = Fido2VaultBinding.init;

    if (!validPolicy(policy))
        return CredentialStatus.invalidInput;

    CredentialStatus status = CredentialStatus.backendFailure;

    status = withNativePin(
        pin,
        (const(char)* pinCString) @trusted
        {
            return enrollImpl(
                devicePath,
                rpId,
                policy,
                pinCString,
                null,
                null,
                binding
            );
        }
    );

    return status;
}

/**
 * Derive one credential-scoped 32-byte hmac-secret wrapping key.
 */
CredentialStatus withFido2WrappingKey(
    string devicePath,
    scope const Fido2VaultBinding binding,
    scope const ubyte[protectorSaltBytes] salt,
    scope SecretCallback visitor
) @safe
{
    return deriveImpl(
        devicePath,
        binding,
        salt,
        null,
        visitor
    );
}

/**
 * Derive a UV-bound hmac-secret without supplying a PIN.
 *
 * The binding must require user verification. This is suitable for
 * authenticators with built-in UV, for example fingerprint verification.
 */
CredentialStatus withFido2WrappingKeyUserVerification(
    string devicePath,
    scope const Fido2VaultBinding binding,
    scope const ubyte[protectorSaltBytes] salt,
    scope SecretCallback visitor
) @safe
{
    if (binding.verificationPolicy !=
        Fido2VerificationPolicy.userVerificationRequired)
        return CredentialStatus.invalidInput;

    return withFido2WrappingKey(
        devicePath,
        binding,
        salt,
        visitor
    );
}

/**
 * Derive a UV-bound hmac-secret using a PIN from SecretBuffer.
 */
CredentialStatus withFido2WrappingKeyWithPin(
    string devicePath,
    scope const Fido2VaultBinding binding,
    scope const ubyte[protectorSaltBytes] salt,
    scope ref const SecretBuffer pin,
    scope SecretCallback visitor
) @safe
{
    if (binding.verificationPolicy !=
        Fido2VerificationPolicy.userVerificationRequired)
        return CredentialStatus.invalidInput;

    CredentialStatus status = CredentialStatus.backendFailure;

    status = withNativePin(
        pin,
        (const(char)* pinCString) @trusted
        {
            return deriveImpl(
                devicePath,
                binding,
                salt,
                pinCString,
                visitor
            );
        }
    );

    return status;
}

version (linux)
{
    /**
     * Enroll a FIDO2 key and create an external unlock envelope for an
     * already-unlocked POSIX vault.
     *
     * The existing passphrase wrapper remains valid as a recovery path.
     */
    CredentialStatus addFido2VaultUnlock(
        EncryptedCredentialVault store,
        string devicePath,
        string rpId,
        Fido2VerificationPolicy policy,
        out VaultUnlockMethod envelope
    ) @safe
    {
        envelope = VaultUnlockMethod.init;

        if (!validPolicy(policy))
            return CredentialStatus.invalidInput;

        if (supportsHmacSecretMakeCredential(devicePath))
            return addFido2VaultUnlockMakeCredentialImpl(
                store,
                devicePath,
                rpId,
                policy,
                null,
                envelope
            );

        Fido2VaultBinding binding;
        auto status = enrollFido2VaultBinding(
            devicePath,
            rpId,
            policy,
            binding
        );
        if (status != CredentialStatus.ok)
            return status;

        const encodedBinding = binding.serialize();

        VaultWrappingKeySource source =
            (scope const ubyte[protectorSaltBytes] salt,
             scope SecretCallback visitor) @safe
            {
                return withFido2WrappingKey(
                    devicePath,
                    binding,
                    salt,
                    visitor
                );
            };

        return createVaultUnlockMethodForStore(
            store,
            fido2ProtectorKind,
            encodedBinding,
            source,
            envelope
        );
    }

    /**
     * Add a user-verification-required FIDO2 unlock envelope without a PIN.
     *
     * This path is intended for authenticators with built-in UV. The
     * authenticator may satisfy UV through fingerprint or another internal
     * modality; credentials-d does not encode the modality in the binding.
     */
    CredentialStatus addFido2UserVerificationVaultUnlock(
        EncryptedCredentialVault store,
        string devicePath,
        string rpId,
        out VaultUnlockMethod envelope
    ) @safe
    {
        return addFido2VaultUnlock(
            store,
            devicePath,
            rpId,
            Fido2VerificationPolicy.userVerificationRequired,
            envelope
        );
    }

    /**
     * Add a touch-only FIDO2 unlock envelope using a PIN only for enrollment.
     *
     * This convenience function is intended for authenticators that require
     * PIN authorization during MakeCredential even though later use is
     * deliberately touch-only. The persisted policy is userPresence/touchOnly.
     *
     * The supplied PIN is used only while creating the authenticator
     * credential and the initial envelope wrapping key. Later unlocks must use
     * unlockVaultWithFido2Touch(), which has no PIN parameter and performs a
     * user-presence-only hmac-secret assertion.
     */
    CredentialStatus addFido2TouchVaultUnlockWithEnrollmentPin(
        EncryptedCredentialVault store,
        string devicePath,
        string rpId,
        scope ref const SecretBuffer enrollmentPin,
        out VaultUnlockMethod envelope
    ) @safe
    {
        return addFido2VaultUnlockWithPin(
            store,
            devicePath,
            rpId,
            Fido2VerificationPolicy.touchOnly,
            enrollmentPin,
            envelope
        );
    }

    /**
     * PIN-assisted enrollment variant of addFido2VaultUnlock.
     *
     * The overload without an explicit policy preserves the original API and
     * means userVerificationRequired. The policy overload also supports
     * PIN-protected CTAP2.0 authenticators that require PIN only while creating
     * an otherwise userPresence binding.
     */
    CredentialStatus addFido2VaultUnlockWithPin(
        EncryptedCredentialVault store,
        string devicePath,
        string rpId,
        scope ref const SecretBuffer pin,
        out VaultUnlockMethod envelope
    ) @safe
    {
        return addFido2VaultUnlockWithPin(
            store,
            devicePath,
            rpId,
            Fido2VerificationPolicy.userVerificationRequired,
            pin,
            envelope
        );
    }

    /// Ditto.
    CredentialStatus addFido2VaultUnlockWithPin(
        EncryptedCredentialVault store,
        string devicePath,
        string rpId,
        Fido2VerificationPolicy policy,
        scope ref const SecretBuffer pin,
        out VaultUnlockMethod envelope
    ) @safe
    {
        envelope = VaultUnlockMethod.init;

        if (!validPolicy(policy))
            return CredentialStatus.invalidInput;

        if (supportsHmacSecretMakeCredential(devicePath))
        {
            CredentialStatus fastStatus = CredentialStatus.backendFailure;
            fastStatus = withNativePin(
                pin,
                (const(char)* pinCString) @trusted
                {
                    return addFido2VaultUnlockMakeCredentialImpl(
                        store,
                        devicePath,
                        rpId,
                        policy,
                        pinCString,
                        envelope
                    );
                }
            );
            return fastStatus;
        }

        Fido2VaultBinding binding;
        auto status = enrollFido2VaultBindingWithPin(
            devicePath,
            rpId,
            policy,
            pin,
            binding
        );
        if (status != CredentialStatus.ok)
            return status;

        const encodedBinding = binding.serialize();

        VaultWrappingKeySource source;

        final switch (policy)
        {
            case Fido2VerificationPolicy.userPresence:
                source =
                    (scope const ubyte[protectorSaltBytes] salt,
                     scope SecretCallback visitor) @safe
                    {
                        return withFido2WrappingKey(
                            devicePath,
                            binding,
                            salt,
                            visitor
                        );
                    };
                break;

            case Fido2VerificationPolicy.userVerificationRequired:
                source =
                    (scope const ubyte[protectorSaltBytes] salt,
                     scope SecretCallback visitor) @safe
                    {
                        return withFido2WrappingKeyWithPin(
                            devicePath,
                            binding,
                            salt,
                            pin,
                            visitor
                        );
                    };
                break;
        }

        return createVaultUnlockMethodForStore(
            store,
            fido2ProtectorKind,
            encodedBinding,
            source,
            envelope
        );
    }

    /**
     * Unlock a POSIX vault through one FIDO2 envelope.
     */
    CredentialStatus unlockVaultWithFido2(
        EncryptedCredentialVault store,
        string devicePath,
        scope const VaultUnlockMethod envelope
    ) @safe
    {
        Fido2VaultBinding binding;
        const status = bindingFromEnvelope(envelope, binding);
        if (status != CredentialStatus.ok)
            return status;

        VaultWrappingKeySource source =
            (scope const ubyte[protectorSaltBytes] salt,
             scope SecretCallback visitor) @safe
            {
                return withFido2WrappingKey(
                    devicePath,
                    binding,
                    salt,
                    visitor
                );
            };

        return unlockVaultWithEnvelope(
            store,
            envelope,
            source
        );
    }

    /**
     * Unlock a POSIX vault with touch-only FIDO2 user presence.
     *
     * No PIN is accepted by this API. A binding enrolled through
     * addFido2TouchVaultUnlockWithEnrollmentPin() therefore needs only the
     * authenticator and a physical touch during normal unlock.
     */
    CredentialStatus unlockVaultWithFido2Touch(
        EncryptedCredentialVault store,
        string devicePath,
        scope const VaultUnlockMethod envelope
    ) @safe
    {
        Fido2VaultBinding binding;
        const status = bindingFromEnvelope(envelope, binding);
        if (status != CredentialStatus.ok)
            return status;

        if (binding.verificationPolicy !=
            Fido2VerificationPolicy.touchOnly)
            return CredentialStatus.invalidInput;

        return unlockVaultWithFido2(
            store,
            devicePath,
            envelope
        );
    }

    /**
     * Unlock a POSIX vault with required user verification and no PIN argument.
     *
     * The binding must use userVerificationRequired. This is the consumer
     * entry point for authenticators with built-in UV such as fingerprint.
     */
    CredentialStatus unlockVaultWithFido2UserVerification(
        EncryptedCredentialVault store,
        string devicePath,
        scope const VaultUnlockMethod envelope
    ) @safe
    {
        Fido2VaultBinding binding;
        const status = bindingFromEnvelope(envelope, binding);
        if (status != CredentialStatus.ok)
            return status;

        if (binding.verificationPolicy !=
            Fido2VerificationPolicy.userVerificationRequired)
            return CredentialStatus.invalidInput;

        return unlockVaultWithFido2(
            store,
            devicePath,
            envelope
        );
    }

    /**
     * UV/PIN variant of unlockVaultWithFido2.
     */
    CredentialStatus unlockVaultWithFido2WithPin(
        EncryptedCredentialVault store,
        string devicePath,
        scope const VaultUnlockMethod envelope,
        scope ref const SecretBuffer pin
    ) @safe
    {
        Fido2VaultBinding binding;
        const status = bindingFromEnvelope(envelope, binding);
        if (status != CredentialStatus.ok)
            return status;

        if (binding.verificationPolicy !=
            Fido2VerificationPolicy.userVerificationRequired)
            return CredentialStatus.invalidInput;

        VaultWrappingKeySource source =
            (scope const ubyte[protectorSaltBytes] salt,
             scope SecretCallback visitor) @safe
            {
                return withFido2WrappingKeyWithPin(
                    devicePath,
                    binding,
                    salt,
                    pin,
                    visitor
                );
            };

        return unlockVaultWithEnvelope(
            store,
            envelope,
            source
        );
    }
}

version (linux)
{
    private bool supportsHmacSecretMakeCredential(
        string devicePath
    ) @safe
    {
        Fido2Capabilities capabilities;
        const status =
            queryFido2Capabilities(
                devicePath,
                capabilities
            );

        return status == CredentialStatus.ok &&
            capabilities.hmacSecret &&
            capabilities.hmacSecretMakeCredentialUsable;
    }

    private CredentialStatus addFido2VaultUnlockMakeCredentialImpl(
        EncryptedCredentialVault store,
        string devicePath,
        string rpId,
        Fido2VerificationPolicy policy,
        const(char)* pin,
        out VaultUnlockMethod envelope
    ) @trusted
    {
        envelope = VaultUnlockMethod.init;

        if (store is null ||
            !validDevicePath(devicePath) ||
            !validRpId(rpId) ||
            !validPolicy(policy))
            return CredentialStatus.invalidInput;

        ubyte[protectorSaltBytes] salt;
        ubyte[32] wrappingKey;
        bool secretReceived;

        scope(exit)
        {
            foreach (i; 0 .. wrappingKey.length)
                volatileStore(
                    wrappingKey.ptr + i,
                    cast(ubyte)0
                );
        }

        if (!secureRandomBytes(salt[]))
            return CredentialStatus.backendFailure;

        Fido2VaultBinding binding;
        const enrollmentStatus = enrollImpl(
            devicePath,
            rpId,
            policy,
            pin,
            salt[],
            (scope const(ubyte)[] secret) @safe
            {
                if (secret.length != wrappingKey.length ||
                    secretReceived)
                    return;

                wrappingKey[] = secret[];
                secretReceived = true;
            },
            binding
        );

        if (enrollmentStatus != CredentialStatus.ok)
            return enrollmentStatus;

        if (!secretReceived)
            return CredentialStatus.backendFailure;

        const encodedBinding = binding.serialize();

        VaultWrappingKeySource source =
            (scope const ubyte[protectorSaltBytes] requestedSalt,
             scope SecretCallback visitor) @safe
            {
                if (visitor is null ||
                    requestedSalt[] != salt[])
                    return CredentialStatus.invalidInput;

                visitor(wrappingKey[]);
                return CredentialStatus.ok;
            };

        return createVaultUnlockMethodForStoreWithSalt(
            store,
            fido2ProtectorKind,
            encodedBinding,
            salt,
            source,
            envelope
        );
    }
}

private CredentialStatus bindingFromEnvelope(
    scope const VaultUnlockMethod envelope,
    out Fido2VaultBinding binding
) @safe
{
    binding = Fido2VaultBinding.init;

    if (!envelope.valid)
        return CredentialStatus.invalidInput;

    const protectorKind = envelope.protectorKind;
    if (protectorKind != fido2ProtectorKind)
        return CredentialStatus.invalidInput;

    const protectorBinding = envelope.protectorBinding;
    if (!Fido2VaultBinding.tryParse(
        protectorBinding,
        binding
    ))
        return CredentialStatus.corruptData;

    return CredentialStatus.ok;
}

private CredentialStatus enrollImpl(
    string devicePath,
    string rpId,
    Fido2VerificationPolicy policy,
    const(char)* pin,
    scope const(ubyte)[] makeCredentialSalt,
    scope SecretCallback makeCredentialVisitor,
    out Fido2VaultBinding binding
) @trusted
{
    binding = Fido2VaultBinding.init;

    if (!validDevicePath(devicePath) ||
        !validRpId(rpId) ||
        !validPolicy(policy))
        return CredentialStatus.invalidInput;

    const useMakeCredentialSecret =
        makeCredentialSalt.length != 0 ||
        makeCredentialVisitor !is null;

    if (useMakeCredentialSecret &&
        (makeCredentialSalt.length != protectorSaltBytes ||
         makeCredentialVisitor is null))
        return CredentialStatus.invalidInput;

    fido_init(FIDO_DISABLE_U2F_FALLBACK);

    auto dev = fido_dev_new();
    if (dev is null)
        return CredentialStatus.backendFailure;

    scope(exit)
    {
        fido_dev_close(dev);
        fido_dev_free(&dev);
    }

    int rc = fido_dev_open(
        dev,
        cast(const(char)*)toStringz(devicePath)
    );
    if (rc != FIDO_OK)
        return mapFidoStatus(rc);

    rc = fido_dev_set_timeout(
        dev,
        defaultFido2TimeoutMilliseconds
    );
    if (rc != FIDO_OK)
        return mapFidoStatus(rc);

    auto cred = fido_cred_new();
    if (cred is null)
        return CredentialStatus.backendFailure;

    scope(exit) fido_cred_free(&cred);

    ubyte[32] clientDataHash;
    ubyte[32] userId;

    if (!secureRandomBytes(clientDataHash[]) ||
        !secureRandomBytes(userId[]))
        return CredentialStatus.backendFailure;

    if ((rc = fido_cred_set_type(cred, COSE_ES256)) != FIDO_OK ||
        (rc = fido_cred_set_clientdata_hash(
            cred,
            clientDataHash.ptr,
            clientDataHash.length
        )) != FIDO_OK ||
        (rc = fido_cred_set_rp(
            cred,
            cast(const(char)*)toStringz(rpId),
            null
        )) != FIDO_OK ||
        (rc = fido_cred_set_user(
            cred,
            userId.ptr,
            userId.length,
            cast(const(char)*)toStringz(compatibilityUserName),
            null,
            null
        )) != FIDO_OK)
        return mapFidoStatus(rc);

    int extensions = FIDO_EXT_HMAC_SECRET;

    final switch (policy)
    {
        case Fido2VerificationPolicy.userPresence:
            // CTAP requires the uv option to be absent when the authenticator
            // does not advertise built-in UV. rk=false is also the default, so
            // both options remain omitted for maximum CTAP2.0 compatibility.
            rc = FIDO_OK;
            break;

        case Fido2VerificationPolicy.userVerificationRequired:
            extensions |= FIDO_EXT_CRED_PROTECT;

            rc = fido_cred_set_uv(
                cred,
                FidoOpt.true_
            );
            if (rc == FIDO_OK)
                rc = fido_cred_set_prot(
                    cred,
                    FIDO_CRED_PROT_UV_REQUIRED
                );
            break;
    }

    if (rc != FIDO_OK)
        return mapFidoStatus(rc);

    if (useMakeCredentialSecret)
    {
        extensions |= FIDO_EXT_HMAC_SECRET_MC;
        rc = setCredentialHmacSalt(
            cred,
            makeCredentialSalt.ptr,
            makeCredentialSalt.length
        );
        if (rc != FIDO_OK)
            return mapFidoStatus(rc);
    }

    rc = fido_cred_set_extensions(cred, extensions);
    if (rc != FIDO_OK)
        return mapFidoStatus(rc);

    rc = fido_dev_make_cred(dev, cred, pin);
    if (rc != FIDO_OK)
    {
        fido_dev_cancel(dev);
        return mapFidoStatus(rc);
    }

    if (useMakeCredentialSecret)
    {
        const flags = fido_cred_flags(cred);
        const uvPerformed =
            (flags & CTAP_AUTHDATA_USER_VERIFIED) != 0;

        final switch (policy)
        {
            case Fido2VerificationPolicy.userPresence:
                if (uvPerformed)
                    return CredentialStatus.unsupported;
                break;

            case Fido2VerificationPolicy.userVerificationRequired:
                if (!uvPerformed)
                    return CredentialStatus.permissionDenied;
                break;
        }

        const secretLength = credentialHmacSecretLength(cred);
        const secret = credentialHmacSecretPointer(cred);

        if (secret is null || secretLength != 32)
            return CredentialStatus.unsupported;

        makeCredentialVisitor(secret[0 .. secretLength]);
    }

    const idLength = fido_cred_id_len(cred);
    const id = fido_cred_id_ptr(cred);

    if (id is null ||
        idLength == 0 ||
        idLength > maximumCredentialIdBytes)
        return CredentialStatus.backendFailure;

    binding = Fido2VaultBinding.trusted(
        rpId,
        id[0 .. idLength],
        policy
    );

    return binding.valid
        ? CredentialStatus.ok
        : CredentialStatus.backendFailure;
}

private CredentialStatus deriveImpl(
    string devicePath,
    scope const Fido2VaultBinding binding,
    scope const ubyte[protectorSaltBytes] salt,
    const(char)* pin,
    scope SecretCallback visitor
) @trusted
{
    if (!validDevicePath(devicePath) ||
        !binding.valid ||
        visitor is null)
        return CredentialStatus.invalidInput;

    fido_init(FIDO_DISABLE_U2F_FALLBACK);

    auto dev = fido_dev_new();
    if (dev is null)
        return CredentialStatus.backendFailure;

    scope(exit)
    {
        fido_dev_close(dev);
        fido_dev_free(&dev);
    }

    int rc = fido_dev_open(
        dev,
        cast(const(char)*)toStringz(devicePath)
    );
    if (rc != FIDO_OK)
        return mapFidoStatus(rc);

    rc = fido_dev_set_timeout(
        dev,
        defaultFido2TimeoutMilliseconds
    );
    if (rc != FIDO_OK)
        return mapFidoStatus(rc);

    auto assertion = fido_assert_new();
    if (assertion is null)
        return CredentialStatus.backendFailure;

    scope(exit) fido_assert_free(&assertion);

    ubyte[32] clientDataHash;
    if (!secureRandomBytes(clientDataHash[]))
        return CredentialStatus.backendFailure;

    const bindingRpId = binding.rpId;
    const bindingCredentialId = binding.credentialId;

    if ((rc = fido_assert_set_clientdata_hash(
            assertion,
            clientDataHash.ptr,
            clientDataHash.length
        )) != FIDO_OK ||
        (rc = fido_assert_set_rp(
            assertion,
            cast(const(char)*)toStringz(bindingRpId)
        )) != FIDO_OK ||
        (rc = fido_assert_allow_cred(
            assertion,
            bindingCredentialId.ptr,
            bindingCredentialId.length
        )) != FIDO_OK ||
        (rc = fido_assert_set_extensions(
            assertion,
            FIDO_EXT_HMAC_SECRET
        )) != FIDO_OK ||
        (rc = fido_assert_set_hmac_salt(
            assertion,
            salt.ptr,
            salt.length
        )) != FIDO_OK ||
        (rc = fido_assert_set_up(
            assertion,
            FidoOpt.true_
        )) != FIDO_OK)
        return mapFidoStatus(rc);

    final switch (binding.verificationPolicy)
    {
        case Fido2VerificationPolicy.userPresence:
            // Do not send uv=false to authenticators that do not advertise
            // built-in UV. Omission has the protocol default of no UV request.
            rc = FIDO_OK;
            break;

        case Fido2VerificationPolicy.userVerificationRequired:
            rc = fido_assert_set_uv(
                assertion,
                FidoOpt.true_
            );
            break;
    }

    if (rc != FIDO_OK)
        return mapFidoStatus(rc);

    rc = fido_dev_get_assert(dev, assertion, pin);
    if (rc != FIDO_OK)
    {
        fido_dev_cancel(dev);
        return mapFidoStatus(rc);
    }

    if (fido_assert_count(assertion) != 1)
        return CredentialStatus.backendFailure;

    const flags = fido_assert_flags(assertion, 0);
    const uvPerformed =
        (flags & CTAP_AUTHDATA_USER_VERIFIED) != 0;

    final switch (binding.verificationPolicy)
    {
        case Fido2VerificationPolicy.userPresence:
            // hmac-secret output is UV-state dependent. If the authenticator
            // forced UV despite an UP-only binding, reject rather than silently
            // switching the derived wrapping-key domain.
            if (uvPerformed)
                return CredentialStatus.unsupported;
            break;

        case Fido2VerificationPolicy.userVerificationRequired:
            if (!uvPerformed)
                return CredentialStatus.permissionDenied;
            break;
    }

    const secretLength =
        fido_assert_hmac_secret_len(assertion, 0);
    const secret =
        fido_assert_hmac_secret_ptr(assertion, 0);

    if (secret is null || secretLength != 32)
        return CredentialStatus.unsupported;

    visitor(secret[0 .. secretLength]);
    return CredentialStatus.ok;
}

private alias FidoCredSetHmacSaltFn =
    extern(C) int function(
        fido_cred_t*,
        const(ubyte)*,
        size_t
    ) @nogc nothrow;
private alias FidoCredHmacSecretPtrFn =
    extern(C) const(ubyte)* function(
        const(fido_cred_t)*
    ) @nogc nothrow;
private alias FidoCredHmacSecretLenFn =
    extern(C) size_t function(
        const(fido_cred_t)*
    ) @nogc nothrow;

private struct HmacSecretMcAbi
{
    FidoCredSetHmacSaltFn setSalt;
    FidoCredHmacSecretPtrFn secretPtr;
    FidoCredHmacSecretLenFn secretLen;

    @property bool available() const
        @nogc nothrow @safe
    {
        return setSalt !is null &&
            secretPtr !is null &&
            secretLen !is null;
    }
}

private HmacSecretMcAbi resolveHmacSecretMcAbi() @trusted
{
    HmacSecretMcAbi abi;

    version (Posix)
    {
        auto handle = dlopen(null, RTLD_LAZY);
        if (handle is null)
            return abi;

        scope(exit) dlclose(handle);

        abi.setSalt = cast(FidoCredSetHmacSaltFn)
            dlsym(handle, "fido_cred_set_hmac_salt".ptr);
        abi.secretPtr = cast(FidoCredHmacSecretPtrFn)
            dlsym(handle, "fido_cred_hmac_secret_ptr".ptr);
        abi.secretLen = cast(FidoCredHmacSecretLenFn)
            dlsym(handle, "fido_cred_hmac_secret_len".ptr);
    }

    return abi;
}

private bool hmacSecretMcAbiAvailable() @trusted
{
    return resolveHmacSecretMcAbi().available;
}

private int setCredentialHmacSalt(
    fido_cred_t* cred,
    const(ubyte)* salt,
    size_t length
) @trusted
{
    const abi = resolveHmacSecretMcAbi();
    if (!abi.available)
        return FIDO_ERR_UNSUPPORTED_EXTENSION;

    return abi.setSalt(cred, salt, length);
}

private const(ubyte)* credentialHmacSecretPointer(
    const fido_cred_t* cred
) @trusted
{
    const abi = resolveHmacSecretMcAbi();
    return abi.available
        ? abi.secretPtr(cred)
        : null;
}

private size_t credentialHmacSecretLength(
    const fido_cred_t* cred
) @trusted
{
    const abi = resolveHmacSecretMcAbi();
    return abi.available
        ? abi.secretLen(cred)
        : 0;
}

private bool hasCborString(
    const(char*)* values,
    size_t count,
    string expected
) @trusted
{
    if (values is null)
        return false;

    foreach (i; 0 .. count)
    {
        const value = values[i];
        if (value !is null &&
            fromStringz(value) == expected)
            return true;
    }

    return false;
}

private bool findCborOption(
    const fido_cbor_info_t* info,
    string expected,
    out bool value
) @trusted
{
    value = false;

    if (info is null)
        return false;

    const names = fido_cbor_info_options_name_ptr(info);
    const values = fido_cbor_info_options_value_ptr(info);
    const count = fido_cbor_info_options_len(info);

    if (names is null || values is null)
        return false;

    foreach (i; 0 .. count)
    {
        const name = names[i];
        if (name !is null &&
            fromStringz(name) == expected)
        {
            value = values[i];
            return true;
        }
    }

    return false;
}

private bool validDevicePath(string path)
    @nogc nothrow @safe
{
    if (path.length == 0)
        return false;

    foreach (char c; path)
        if (c == '\0')
            return false;

    return true;
}

private bool validPolicy(Fido2VerificationPolicy policy)
    @nogc nothrow pure @safe
{
    return
        policy == Fido2VerificationPolicy.userPresence ||
        policy ==
            Fido2VerificationPolicy.userVerificationRequired;
}

private alias NativePinOperation =
    CredentialStatus delegate(const(char)* pin) @trusted;

private CredentialStatus withNativePin(
    scope ref const SecretBuffer pin,
    scope NativePinOperation operation
) @trusted
{
    if (operation is null || pin.empty)
        return CredentialStatus.invalidInput;

    CredentialStatus status = CredentialStatus.invalidInput;

    pin.withBytes((scope const(ubyte)[] bytes) @safe
    {
        status = runWithNativePinBytes(bytes, operation);
    });

    return status;
}

private CredentialStatus runWithNativePinBytes(
    scope const(ubyte)[] bytes,
    scope NativePinOperation operation
) @trusted
{
    if (operation is null ||
        bytes.length == 0 ||
        bytes.length > 255)
        return CredentialStatus.invalidInput;

    foreach (ubyte value; bytes)
        if (value == 0)
            return CredentialStatus.invalidInput;

    auto buffer = cast(char*)malloc(bytes.length + 1);
    if (buffer is null)
        onOutOfMemoryError();

    scope(exit)
    {
        foreach (i; 0 .. bytes.length + 1)
            volatileStore(
                cast(ubyte*)buffer + i,
                cast(ubyte)0
            );
        free(buffer);
    }

    foreach (i, value; bytes)
        buffer[i] = cast(char)value;
    buffer[bytes.length] = '\0';

    return operation(buffer);
}

private string copyCString(const(char)* value) @trusted
{
    if (value is null)
        return null;

    return fromStringz(value).idup;
}

private CredentialStatus mapFidoStatus(int status)
    @nogc nothrow @safe
{
    switch (status)
    {
        case FIDO_OK:
            return CredentialStatus.ok;

        case FIDO_ERR_UNSUPPORTED_EXTENSION:
        case FIDO_ERR_UNSUPPORTED_ALGORITHM:
        case FIDO_ERR_UNSUPPORTED_OPTION:
        case FIDO_ERR_INVALID_OPTION:
            return CredentialStatus.unsupported;

        case FIDO_ERR_NO_CREDENTIALS:
        case FIDO_ERR_INVALID_CREDENTIAL:
        case FIDO_ERR_NOTFOUND:
            return CredentialStatus.notFound;

        case FIDO_ERR_PIN_REQUIRED:
        case FIDO_ERR_PIN_NOT_SET:
        case FIDO_ERR_UP_REQUIRED:
        case FIDO_ERR_USER_PRESENCE_REQUIRED:
        case FIDO_ERR_USER_ACTION_PENDING:
        case FIDO_ERR_OPERATION_PENDING:
            return CredentialStatus.interactionRequired;

        case FIDO_ERR_KEEPALIVE_CANCEL:
        case FIDO_ERR_OPERATION_DENIED:
        case FIDO_ERR_NOT_ALLOWED:
        case FIDO_ERR_USER_ACTION_TIMEOUT:
        case FIDO_ERR_ACTION_TIMEOUT:
            return CredentialStatus.userCancelled;

        case FIDO_ERR_PIN_INVALID:
        case FIDO_ERR_PIN_BLOCKED:
        case FIDO_ERR_PIN_AUTH_INVALID:
        case FIDO_ERR_PIN_AUTH_BLOCKED:
        case FIDO_ERR_PIN_POLICY_VIOLATION:
        case FIDO_ERR_PIN_TOKEN_EXPIRED:
        case FIDO_ERR_UV_BLOCKED:
        case FIDO_ERR_UV_INVALID:
        case FIDO_ERR_UNAUTHORIZED_PERM:
            return CredentialStatus.permissionDenied;

        case FIDO_ERR_INVALID_COMMAND:
        case FIDO_ERR_INVALID_PARAMETER:
        case FIDO_ERR_INVALID_LENGTH:
        case FIDO_ERR_MISSING_PARAMETER:
        case FIDO_ERR_INVALID_PARAM:
        case FIDO_ERR_INVALID_ARGUMENT:
            return CredentialStatus.invalidInput;

        case FIDO_ERR_LIMIT_EXCEEDED:
        case FIDO_ERR_REQUEST_TOO_LARGE:
            return CredentialStatus.tooLarge;

        case FIDO_ERR_TIMEOUT:
        case FIDO_ERR_CHANNEL_BUSY:
        case FIDO_ERR_INVALID_SEQ:
        case FIDO_ERR_LOCK_REQUIRED:
        case FIDO_ERR_INVALID_CHANNEL:
        case FIDO_ERR_CBOR_UNEXPECTED_TYPE:
        case FIDO_ERR_INVALID_CBOR:
        case FIDO_ERR_PROCESSING:
        case FIDO_ERR_NO_OPERATIONS:
        case FIDO_ERR_NOT_BUSY:
        case FIDO_ERR_NO_OPERATION_PENDING:
        case FIDO_ERR_ERR_OTHER:
        case FIDO_ERR_TX:
        case FIDO_ERR_RX:
        case FIDO_ERR_RX_NOT_CBOR:
        case FIDO_ERR_RX_INVALID_CBOR:
        case FIDO_ERR_INVALID_SIG:
        case FIDO_ERR_INTERNAL:
        case FIDO_ERR_COMPRESS:
        case FIDO_ERR_CREDENTIAL_EXCLUDED:
        case FIDO_ERR_FP_DATABASE_FULL:
        case FIDO_ERR_LARGEBLOB_STORAGE_FULL:
        case FIDO_ERR_KEY_STORE_FULL:
            return CredentialStatus.backendFailure;

        default:
            return CredentialStatus.backendFailure;
    }
}

@("FIDO2 UV convenience path rejects touch-only bindings before hardware")
unittest
{
    auto binding = Fido2VaultBinding.trusted(
        "credentials-d.local",
        [cast(ubyte)1, 2, 3, 4],
        Fido2VerificationPolicy.touchOnly
    );

    ubyte[protectorSaltBytes] salt;

    bool called;
    const status = withFido2WrappingKeyUserVerification(
        "/dev/this-path-must-not-be-opened",
        binding,
        salt,
        (scope const(ubyte)[]) @safe
        {
            called = true;
        }
    );

    assert(status == CredentialStatus.invalidInput);
    assert(!called);
}

@("libfido2 status mapping is fail-closed")
unittest
{
    assert(
        mapFidoStatus(FIDO_ERR_UNSUPPORTED_EXTENSION) ==
        CredentialStatus.unsupported
    );
    assert(
        mapFidoStatus(FIDO_ERR_PIN_REQUIRED) ==
        CredentialStatus.interactionRequired
    );
    assert(
        mapFidoStatus(FIDO_ERR_PIN_INVALID) ==
        CredentialStatus.permissionDenied
    );
    assert(
        mapFidoStatus(FIDO_ERR_NO_CREDENTIALS) ==
        CredentialStatus.notFound
    );
}
