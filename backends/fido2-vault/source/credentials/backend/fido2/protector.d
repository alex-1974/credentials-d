/**
 * FIDO2 hmac-secret vault-key protector.
 */
module credentials.backend.fido2.protector;

import core.exception : onOutOfMemoryError;
import core.stdc.stdlib : free, malloc;
import core.volatile : volatileStore;
import credentials.backend.fido2.binding :
    Fido2VaultBinding,
    Fido2VerificationPolicy,
    fido2ProtectorKind,
    maximumCredentialIdBytes,
    validRpId;
import credentials.backend.fido2.ffi;
import credentials.backend.vault.protector :
    VaultUnlockEnvelope,
    VaultWrappingKeySource,
    protectorSaltBytes;
import credentials.namespace : CredentialNamespace;
import credentials.random : secureRandomBytes;
import credentials.secret : SecretBuffer;
import credentials.store :
    CredentialStatus,
    SecretVisitor;
import std.string : fromStringz, toStringz;

version (linux)
{
    import credentials.backend.vault.posix_protector :
        createVaultUnlockEnvelopeForStore,
        unlockVaultWithEnvelope;
    import credentials.backend.vault.posix_store :
        EncryptedVaultCredentialStore;
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
    scope SecretVisitor visitor
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
 * Derive a UV-bound hmac-secret using a PIN from SecretBuffer.
 */
CredentialStatus withFido2WrappingKeyWithPin(
    string devicePath,
    scope const Fido2VaultBinding binding,
    scope const ubyte[protectorSaltBytes] salt,
    scope ref const SecretBuffer pin,
    scope SecretVisitor visitor
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
        EncryptedVaultCredentialStore store,
        string devicePath,
        string rpId,
        Fido2VerificationPolicy policy,
        out VaultUnlockEnvelope envelope
    ) @safe
    {
        envelope = VaultUnlockEnvelope.init;

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
             scope SecretVisitor visitor) @safe
            {
                return withFido2WrappingKey(
                    devicePath,
                    binding,
                    salt,
                    visitor
                );
            };

        return createVaultUnlockEnvelopeForStore(
            store,
            fido2ProtectorKind,
            encodedBinding,
            source,
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
        EncryptedVaultCredentialStore store,
        string devicePath,
        string rpId,
        scope ref const SecretBuffer enrollmentPin,
        out VaultUnlockEnvelope envelope
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
        EncryptedVaultCredentialStore store,
        string devicePath,
        string rpId,
        scope ref const SecretBuffer pin,
        out VaultUnlockEnvelope envelope
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
        EncryptedVaultCredentialStore store,
        string devicePath,
        string rpId,
        Fido2VerificationPolicy policy,
        scope ref const SecretBuffer pin,
        out VaultUnlockEnvelope envelope
    ) @safe
    {
        envelope = VaultUnlockEnvelope.init;

        if (!validPolicy(policy))
            return CredentialStatus.invalidInput;

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
                     scope SecretVisitor visitor) @safe
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
                     scope SecretVisitor visitor) @safe
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

        return createVaultUnlockEnvelopeForStore(
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
        EncryptedVaultCredentialStore store,
        string devicePath,
        scope const VaultUnlockEnvelope envelope
    ) @safe
    {
        Fido2VaultBinding binding;
        const status = bindingFromEnvelope(envelope, binding);
        if (status != CredentialStatus.ok)
            return status;

        VaultWrappingKeySource source =
            (scope const ubyte[protectorSaltBytes] salt,
             scope SecretVisitor visitor) @safe
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
        EncryptedVaultCredentialStore store,
        string devicePath,
        scope const VaultUnlockEnvelope envelope
    ) @safe
    {
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
        EncryptedVaultCredentialStore store,
        string devicePath,
        scope const VaultUnlockEnvelope envelope,
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
             scope SecretVisitor visitor) @safe
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

private CredentialStatus bindingFromEnvelope(
    scope const VaultUnlockEnvelope envelope,
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
    out Fido2VaultBinding binding
) @trusted
{
    binding = Fido2VaultBinding.init;

    if (!validDevicePath(devicePath) ||
        !validRpId(rpId) ||
        !validPolicy(policy))
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

    rc = fido_cred_set_extensions(cred, extensions);
    if (rc != FIDO_OK)
        return mapFidoStatus(rc);

    rc = fido_dev_make_cred(dev, cred, pin);
    if (rc != FIDO_OK)
    {
        fido_dev_cancel(dev);
        return mapFidoStatus(rc);
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
    scope SecretVisitor visitor
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
