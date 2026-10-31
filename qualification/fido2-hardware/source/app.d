module app;

version (linux):

import core.sys.posix.termios : ECHO, TCSANOW, tcgetattr, tcsetattr, termios;
import core.sys.posix.unistd : STDIN_FILENO, getpid, isatty;
import core.volatile : volatileStore;
import credentials :
    CredentialHandle,
    CredentialNamespace,
    CredentialStatus,
    SecretBuffer,
    SecretCallback;
import credentials.backend.fido2.binding :
    Fido2VaultBinding,
    Fido2VerificationPolicy,
    fido2ProtectorKind;
import credentials.backend.fido2.protector :
    Fido2Capabilities,
    Fido2DeviceInfo,
    addFido2TouchVaultUnlockWithEnrollmentPin,
    addFido2UserVerificationVaultUnlock,
    addFido2VaultUnlock,
    addFido2VaultUnlockWithPin,
    discoverFido2Devices,
    queryFido2Capabilities,
    enrollFido2VaultBinding,
    enrollFido2VaultBindingWithPin,
    enrollFido2VaultBindingWithUserVerification,
    unlockVaultWithFido2,
    unlockVaultWithFido2Touch,
    unlockVaultWithFido2UserVerification,
    unlockVaultWithFido2WithPin,
    withFido2WrappingKey,
    withFido2WrappingKeyUserVerification,
    withFido2WrappingKeyWithPin;
import credentials.vault :
    EncryptedCredentialVault,
    VaultUnlockMethod;
import credentials.backend.vault.posix_protector :
    createVaultUnlockMethodForStore;
import credentials.backend.vault.protector :
    VaultWrappingKeySource,
    protectorSaltBytes;
import std.conv : to;
import std.file :
    exists,
    mkdirRecurse,
    read,
    remove,
    write;
import std.path : buildPath;
import std.stdio :
    stdin,
    stderr,
    stdout,
    writeln;

private enum string defaultRpId =
    "credentials-d.local";

private void report(Args...)(Args args)
{
    stdout.writeln(args);
    stdout.flush();
}

private void promptTouch(string action)
{
    stderr.writeln(
        "ACTION_REQUIRED=",
        action,
        " Release the sensor, wait for blinking, then touch once."
    );
    stderr.flush();
}

private struct Options
{
    bool discoverOnly;
    bool uv;
    bool builtInUv;
    bool confirmRemoveA;
    string deviceA;
    string deviceB;
    string rpId = defaultRpId;
    string workDir = "/tmp";
}

private CredentialNamespace namespaceOf(string value)
{
    CredentialNamespace ns;
    enforce(
        CredentialNamespace.tryParse(value, ns),
        "invalid qualification namespace"
    );
    return ns;
}

private void enforce(bool condition, string message) @trusted
{
    if (!condition)
    {
        stderr.writeln("QUALIFICATION_ERROR=", message);
        throw new Exception(message);
    }
}

private void enforceStatus(
    CredentialStatus actual,
    CredentialStatus expected,
    string operation
) @trusted
{
    if (actual != expected)
    {
        stderr.writeln(
            "QUALIFICATION_ERROR=",
            operation,
            " expected=",
            cast(int) expected,
            " actual=",
            cast(int) actual
        );
        throw new Exception(operation);
    }
}

private Options parseOptions(string[] args)
{
    Options options;

    for (size_t i = 1; i < args.length; ++i)
    {
        const arg = args[i];

        if (arg == "--discover-only")
        {
            options.discoverOnly = true;
        }
        else if (arg == "--uv")
        {
            options.uv = true;
        }
        else if (arg == "--uv-built-in")
        {
            options.builtInUv = true;
        }
        else if (arg == "--confirm-remove-a")
        {
            options.confirmRemoveA = true;
        }
        else if (arg == "--device-a")
        {
            enforce(++i < args.length, "--device-a requires a value");
            options.deviceA = args[i];
        }
        else if (arg == "--device-b")
        {
            enforce(++i < args.length, "--device-b requires a value");
            options.deviceB = args[i];
        }
        else if (arg == "--rp-id")
        {
            enforce(++i < args.length, "--rp-id requires a value");
            options.rpId = args[i];
        }
        else if (arg == "--work-dir")
        {
            enforce(++i < args.length, "--work-dir requires a value");
            options.workDir = args[i];
        }
        else
        {
            enforce(false, "unknown argument: " ~ arg);
        }
    }

    enforce(
        !(options.uv && options.builtInUv),
        "--uv and --uv-built-in are mutually exclusive"
    );

    return options;
}

private bool requiresUserVerification(const Options options)
    @nogc nothrow pure @safe
{
    return options.uv || options.builtInUv;
}

private Fido2DeviceInfo[] discover()
{
    Fido2DeviceInfo[] devices;
    enforceStatus(
        discoverFido2Devices(devices),
        CredentialStatus.ok,
        "discoverFido2Devices"
    );
    return devices;
}

private bool findDevice(
    scope const Fido2DeviceInfo[] devices,
    string path,
    out Fido2DeviceInfo result
) @safe
{
    result = Fido2DeviceInfo.init;

    foreach (const device; devices)
    {
        if (device.path == path)
        {
            result = device;
            return true;
        }
    }

    return false;
}

private bool selectPrimaryDevice(
    scope const Fido2DeviceInfo[] devices,
    string requestedPath,
    out Fido2DeviceInfo result,
    out string selectedPath
) @safe
{
    result = Fido2DeviceInfo.init;
    selectedPath = null;

    if (requestedPath.length == 0 || requestedPath == "auto")
    {
        if (devices.length != 1)
            return false;

        result = devices[0];
        selectedPath = result.path;
        return selectedPath.length != 0;
    }

    if (!findDevice(devices, requestedPath, result))
        return false;

    selectedPath = result.path;
    return selectedPath.length != 0;
}

private bool containsBytes(
    scope const(ubyte)[] haystack,
    scope const(ubyte)[] needle
) @safe
{
    if (needle.length == 0)
        return true;

    if (needle.length > haystack.length)
        return false;

    foreach (i; 0 .. haystack.length - needle.length + 1)
    {
        bool equal = true;
        foreach (j; 0 .. needle.length)
        {
            if (haystack[i + j] != needle[j])
            {
                equal = false;
                break;
            }
        }

        if (equal)
            return true;
    }

    return false;
}

private void wipe(scope ubyte[] bytes) nothrow @nogc @trusted
{
    foreach (i; 0 .. bytes.length)
        volatileStore(bytes.ptr + i, cast(ubyte)0);
}

private SecretBuffer readPin()
{
    stderr.writeln(
        "ACTION_REQUIRED=Enter authenticator PIN (input hidden). The PIN is not printed or included in receipts."
    );
    stderr.flush();

    enforce(
        isatty(STDIN_FILENO) == 1,
        "protected PIN input requires an interactive terminal"
    );

    termios original;
    enforce(
        tcgetattr(STDIN_FILENO, &original) == 0,
        "unable to read terminal settings for protected PIN input"
    );

    auto hidden = original;
    hidden.c_lflag &= ~ECHO;

    enforce(
        tcsetattr(STDIN_FILENO, TCSANOW, &hidden) == 0,
        "unable to disable terminal echo for protected PIN input"
    );

    bool restored;
    scope(exit)
    {
        if (!restored)
        {
            tcsetattr(STDIN_FILENO, TCSANOW, &original);
            stderr.writeln();
        }
    }

    auto line = stdin.readln();

    const restoreResult =
        tcsetattr(STDIN_FILENO, TCSANOW, &original);
    restored = true;
    stderr.writeln();

    enforce(
        restoreResult == 0,
        "unable to restore terminal settings after protected PIN input"
    );
    enforce(line.length != 0, "PIN input missing");

    scope(exit)
    {
        if (line.length != 0)
            wipe(cast(ubyte[])line);
    }

    while (line.length != 0 &&
           (line[$ - 1] == '\n' || line[$ - 1] == '\r'))
        line.length -= 1;

    enforce(line.length != 0, "PIN must not be empty");

    return SecretBuffer(cast(const(ubyte)[])line);
}

private SecretBuffer wrongPinFrom(
    scope ref const SecretBuffer correct
)
{
    ubyte[256] bytes;
    size_t length;

    correct.withBytes((scope const(ubyte)[] current) @safe
    {
        enforce(
            current.length != 0 && current.length <= bytes.length,
            "PIN length outside qualification harness bounds"
        );

        length = current.length;
        bytes[0 .. length] = current[];
    });

    scope(exit) wipe(bytes[]);

    bytes[0] ^= 0x01;
    if (bytes[0] == 0)
        bytes[0] = 0x01;

    return SecretBuffer(bytes[0 .. length]);
}

private CredentialStatus enroll(
    const Options options,
    string devicePath,
    scope ref const SecretBuffer pin,
    string touchAction,
    out Fido2VaultBinding binding
)
{
    const policy = requiresUserVerification(options)
        ? Fido2VerificationPolicy.userVerificationRequired
        : Fido2VerificationPolicy.touchOnly;

    promptTouch(touchAction);

    if (options.builtInUv)
        return enrollFido2VaultBindingWithUserVerification(
            devicePath,
            options.rpId,
            binding
        );

    if (!pin.empty)
        return enrollFido2VaultBindingWithPin(
            devicePath,
            options.rpId,
            policy,
            pin,
            binding
        );

    return enrollFido2VaultBinding(
        devicePath,
        options.rpId,
        policy,
        binding
    );
}

private CredentialStatus deriveCore(
    const Options options,
    string devicePath,
    scope const Fido2VaultBinding binding,
    scope const ubyte[protectorSaltBytes] salt,
    scope ref const SecretBuffer pin,
    ref ubyte[32] output
) @safe
{
    bool called;
    CredentialStatus status;

    auto visitor = (scope const(ubyte)[] bytes) @safe
    {
        enforce(bytes.length == output.length, "unexpected hmac-secret length");
        output[] = bytes[];
        called = true;
    };

    if (options.uv)
        status = withFido2WrappingKeyWithPin(
            devicePath,
            binding,
            salt,
            pin,
            visitor
        );
    else if (options.builtInUv)
        status = withFido2WrappingKeyUserVerification(
            devicePath,
            binding,
            salt,
            visitor
        );
    else
        status = withFido2WrappingKey(
            devicePath,
            binding,
            salt,
            visitor
        );

    if (status == CredentialStatus.ok)
        enforce(called, "hmac-secret visitor not called on success");
    else
        enforce(!called, "hmac-secret visitor called on failure");

    return status;
}

private CredentialStatus derive(
    const Options options,
    string devicePath,
    scope const Fido2VaultBinding binding,
    scope const ubyte[protectorSaltBytes] salt,
    scope ref const SecretBuffer pin,
    string touchAction,
    ref ubyte[32] output
)
{
    promptTouch(touchAction);
    return deriveCore(
        options,
        devicePath,
        binding,
        salt,
        pin,
        output
    );
}

private CredentialStatus addEnvelope(
    const Options options,
    EncryptedCredentialVault store,
    string devicePath,
    scope ref const SecretBuffer pin,
    string label,
    out VaultUnlockMethod envelope
)
{
    Fido2Capabilities capabilities;
    const capabilityStatus =
        queryFido2Capabilities(
            devicePath,
            capabilities
        );

    if (capabilityStatus == CredentialStatus.ok &&
        capabilities.hmacSecretMakeCredentialUsable)
    {
        report(label, "_enrollment_path=hmac-secret-mc");
        promptTouch(
            label ~
            " hmac-secret-mc credential enrollment and key derivation."
        );

        if (options.uv)
        {
            return addFido2VaultUnlockWithPin(
                store,
                devicePath,
                options.rpId,
                Fido2VerificationPolicy.userVerificationRequired,
                pin,
                envelope
            );
        }

        if (options.builtInUv)
        {
            return addFido2UserVerificationVaultUnlock(
                store,
                devicePath,
                options.rpId,
                envelope
            );
        }

        if (!pin.empty)
        {
            return addFido2TouchVaultUnlockWithEnrollmentPin(
                store,
                devicePath,
                options.rpId,
                pin,
                envelope
            );
        }

        return addFido2VaultUnlock(
            store,
            devicePath,
            options.rpId,
            Fido2VerificationPolicy.touchOnly,
            envelope
        );
    }

    report(label, "_enrollment_path=makecredential-plus-getassertion");

    envelope = VaultUnlockMethod.init;

    Fido2VaultBinding binding;
    auto status = enroll(
        options,
        devicePath,
        pin,
        label ~ " credential enrollment.",
        binding
    );
    if (status != CredentialStatus.ok)
        return status;

    const encodedBinding = binding.serialize();

    VaultWrappingKeySource source =
        (scope const ubyte[protectorSaltBytes] salt,
         scope SecretCallback visitor) @safe
        {
            ubyte[32] output;
            scope(exit) wipe(output[]);

            const deriveStatus = deriveCore(
                options,
                devicePath,
                binding,
                salt,
                pin,
                output
            );
            if (deriveStatus != CredentialStatus.ok)
                return deriveStatus;

            visitor(output[]);
            return CredentialStatus.ok;
        };

    promptTouch(label ~ " hmac-secret key derivation.");

    return createVaultUnlockMethodForStore(
        store,
        fido2ProtectorKind,
        encodedBinding,
        source,
        envelope
    );
}

private CredentialStatus unlockEnvelope(
    const Options options,
    EncryptedCredentialVault store,
    string devicePath,
    scope const VaultUnlockMethod envelope,
    scope ref const SecretBuffer pin,
    string touchAction
)
{
    promptTouch(touchAction);

    if (options.uv)
        return unlockVaultWithFido2WithPin(
            store,
            devicePath,
            envelope,
            pin
        );

    if (options.builtInUv)
        return unlockVaultWithFido2UserVerification(
            store,
            devicePath,
            envelope
        );

    return unlockVaultWithFido2Touch(
        store,
        devicePath,
        envelope
    );
}

private void printDevice(string label, scope const Fido2DeviceInfo device)
{
    report(label, "_manufacturer=", device.manufacturer);
    report(label, "_product=", device.product);
}

private void printCapabilities(
    string label,
    scope const Fido2Capabilities capabilities
)
{
    report(label, "_hmac_secret=", capabilities.hmacSecret);
    report(
        label,
        "_hmac_secret_make_credential=",
        capabilities.hmacSecretMakeCredential
    );
    report(
        label,
        "_hmac_secret_make_credential_usable=",
        capabilities.hmacSecretMakeCredentialUsable
    );
    report(label, "_cred_protect=", capabilities.credProtect);
    report(
        label,
        "_client_pin_supported=",
        capabilities.clientPinSupported
    );
    report(
        label,
        "_client_pin_configured=",
        capabilities.clientPinConfigured
    );
    report(
        label,
        "_built_in_uv_supported=",
        capabilities.builtInUserVerificationSupported
    );
    report(
        label,
        "_built_in_uv_configured=",
        capabilities.builtInUserVerificationConfigured
    );
    report(label, "_uv_modality=", capabilities.uvModality);
    report(
        label,
        "_discoverable_credentials_supported=",
        capabilities.discoverableCredentialsSupported
    );
    report(
        label,
        "_discoverable_credentials_remaining=",
        capabilities.remainingDiscoverableCredentials
    );
    report(label, "_algorithm_es256=", capabilities.es256);
    report(label, "_algorithm_eddsa=", capabilities.edDsa);
    report(label, "_algorithm_es384=", capabilities.es384);
    report(label, "_algorithm_rs256=", capabilities.rs256);
    report(label, "_firmware_version_raw=", capabilities.firmwareVersion);
}

private bool findDevicePresent(
    scope const Fido2DeviceInfo[] devices,
    string path
) @safe
{
    Fido2DeviceInfo ignored;
    return findDevice(devices, path, ignored);
}

private VaultUnlockMethod withReplacementBinding(
    scope const VaultUnlockMethod original,
    scope const Fido2VaultBinding replacement
)
{
    const originalBytes = original.serialize();
    const oldBinding = original.protectorBinding;
    const newBinding = replacement.serialize();

    enforce(
        oldBinding.length <= originalBytes.length,
        "protector binding longer than serialized envelope"
    );

    const bindingOffset =
        originalBytes.length - oldBinding.length;

    enforce(
        originalBytes[bindingOffset .. $] == oldBinding[],
        "serialized envelope binding is not the final field"
    );

    enforce(
        newBinding.length <= uint.max,
        "replacement protector binding too large"
    );

    auto rewritten =
        new ubyte[bindingOffset + newBinding.length];
    rewritten[0 .. bindingOffset] =
        originalBytes[0 .. bindingOffset];

    enum size_t bindingLengthOffset = 8 + 2 + 2;
    const length = cast(uint)newBinding.length;

    rewritten[bindingLengthOffset + 0] =
        cast(ubyte)length;
    rewritten[bindingLengthOffset + 1] =
        cast(ubyte)(length >> 8);
    rewritten[bindingLengthOffset + 2] =
        cast(ubyte)(length >> 16);
    rewritten[bindingLengthOffset + 3] =
        cast(ubyte)(length >> 24);

    rewritten[bindingOffset .. $] = newBinding[];

    VaultUnlockMethod result;
    enforce(
        VaultUnlockMethod.tryParse(rewritten, result),
        "wrong-credential envelope did not parse"
    );
    return result;
}


private void waitForRemoval(string deviceA)
{
    stderr.writeln(
        "ACTION_REQUIRED=Unplug security key A, then press Enter."
    );
    stderr.flush();
    stdin.readln();

    const devices = discover();
    enforce(
        !findDevicePresent(devices, deviceA),
        "security key A is still discoverable after removal confirmation"
    );
}

void main(string[] args)
{
    stderr.writeln("qualification_start=fido2-hardware-v1");

    const options = parseOptions(args);
    stderr.writeln("qualification_stage=options-parsed");

    const devices = discover();
    stderr.writeln("qualification_stage=discovery-complete");

    report("qualification=fido2-hardware-v1");
    report("d_frontend=", __VERSION__);
    report("discovered_devices=", devices.length);

    if (options.discoverOnly)
    {
        foreach (i, ref const device; devices)
        {
            report("device_index=", i);
            report("device_path=", device.path);
            printDevice("device", device);

            Fido2Capabilities capabilities;
            enforceStatus(
                queryFido2Capabilities(
                    device.path,
                    capabilities
                ),
                CredentialStatus.ok,
                "query FIDO2 device capabilities"
            );
            printCapabilities("device", capabilities);
        }

        report("result=DISCOVERY_ONLY");
        return;
    }

    Fido2DeviceInfo deviceAInfo;
    string selectedDeviceA;
    enforce(
        selectPrimaryDevice(
            devices,
            options.deviceA,
            deviceAInfo,
            selectedDeviceA
        ),
        options.deviceA.length == 0 || options.deviceA == "auto"
            ? "automatic device selection requires exactly one discoverable FIDO2 device"
            : "device A is not currently discoverable"
    );

    report("device_a_path=", selectedDeviceA);

    Fido2DeviceInfo deviceBInfo;
    bool hasDeviceB;
    if (options.deviceB.length != 0)
    {
        enforce(
            options.deviceB != selectedDeviceA,
            "device B must be a different runtime device"
        );
        hasDeviceB =
            findDevice(devices, options.deviceB, deviceBInfo);
        enforce(hasDeviceB, "device B is not currently discoverable");
    }

    report(
        "policy=",
        options.uv
            ? "uv-required-pin"
            : options.builtInUv
                ? "uv-required-built-in"
                : "touch-only"
    );
    printDevice("device_a", deviceAInfo);

    Fido2Capabilities deviceACapabilities;
    enforceStatus(
        queryFido2Capabilities(
            selectedDeviceA,
            deviceACapabilities
        ),
        CredentialStatus.ok,
        "query device A capabilities"
    );
    printCapabilities("device_a", deviceACapabilities);

    if (options.builtInUv &&
        (!deviceACapabilities.builtInUserVerificationSupported ||
         !deviceACapabilities.builtInUserVerificationConfigured))
    {
        report("result=UNSUPPORTED");
        report("unsupported_stage=built-in-user-verification");
        return;
    }

    if (hasDeviceB)
    {
        printDevice("device_b", deviceBInfo);

        Fido2Capabilities deviceBCapabilities;
        enforceStatus(
            queryFido2Capabilities(
                options.deviceB,
                deviceBCapabilities
            ),
            CredentialStatus.ok,
            "query device B capabilities"
        );
        printCapabilities("device_b", deviceBCapabilities);
    }

    auto pin = options.uv
        ? readPin()
        : SecretBuffer.init;

    Fido2VaultBinding deterministicBinding;
    auto enrollmentStatus = enroll(
        options,
        selectedDeviceA,
        pin,
        "Initial deterministic credential enrollment.",
        deterministicBinding
    );

    if (!requiresUserVerification(options) &&
        enrollmentStatus == CredentialStatus.interactionRequired &&
        pin.empty)
    {
        stderr.writeln(
            "creation_pin_required=YES (CTAP2 authenticator requires PIN for MakeCredential; later user-presence hmac-secret derivation remains PIN-less)"
        );
        stderr.flush();
        pin = readPin();

        enrollmentStatus = enroll(
            options,
            selectedDeviceA,
            pin,
            "Retry deterministic credential enrollment after PIN authorization.",
            deterministicBinding
        );
    }

    if (enrollmentStatus == CredentialStatus.unsupported)
    {
        report("result=UNSUPPORTED");
        report("unsupported_stage=enrollment-policy");
        return;
    }

    enforceStatus(
        enrollmentStatus,
        CredentialStatus.ok,
        "FIDO2 deterministic-test enrollment"
    );

    const serializedBinding = deterministicBinding.serialize();
    enforce(
        !containsBytes(
            serializedBinding,
            cast(const(ubyte)[])selectedDeviceA
        ),
        "persisted FIDO2 binding contains the runtime device path"
    );

    Fido2VaultBinding parsedBinding;
    enforce(
        Fido2VaultBinding.tryParse(
            serializedBinding,
            parsedBinding
        ),
        "FIDO2 binding round-trip failed"
    );

    ubyte[protectorSaltBytes] salt1;
    ubyte[protectorSaltBytes] salt2;
    foreach (i; 0 .. protectorSaltBytes)
    {
        salt1[i] = cast(ubyte)i;
        salt2[i] = cast(ubyte)(i + 1);
    }

    ubyte[32] key1;
    ubyte[32] key1Repeat;
    ubyte[32] key2;
    scope(exit)
    {
        wipe(key1[]);
        wipe(key1Repeat[]);
        wipe(key2[]);
    }

    enforceStatus(
        derive(
            options,
            selectedDeviceA,
            parsedBinding,
            salt1,
            pin,
            "hmac-secret derivation 1/3 (baseline salt).",
            key1
        ),
        CredentialStatus.ok,
        "first hmac-secret derivation"
    );
    enforceStatus(
        derive(
            options,
            selectedDeviceA,
            parsedBinding,
            salt1,
            pin,
            "hmac-secret derivation 2/3 (repeat baseline salt).",
            key1Repeat
        ),
        CredentialStatus.ok,
        "repeated hmac-secret derivation"
    );
    enforceStatus(
        derive(
            options,
            selectedDeviceA,
            parsedBinding,
            salt2,
            pin,
            "hmac-secret derivation 3/3 (different salt).",
            key2
        ),
        CredentialStatus.ok,
        "different-salt hmac-secret derivation"
    );

    enforce(
        key1[] == key1Repeat[],
        "same credential + salt did not reproduce the hmac-secret"
    );
    enforce(
        key1[] != key2[],
        "different salts produced the same hmac-secret"
    );

    report("hmac_same_salt=PASS");
    report("hmac_different_salt=PASS");
    report("device_path_not_persisted=PASS");

    if (options.uv)
    {
        auto wrongPin = wrongPinFrom(pin);
        ubyte[32] wrongPinOutput;
        scope(exit) wipe(wrongPinOutput[]);

        const wrongPinStatus = derive(
            options,
            selectedDeviceA,
            parsedBinding,
            salt1,
            wrongPin,
            "UV wrong-PIN rejection check.",
            wrongPinOutput
        );

        enforceStatus(
            wrongPinStatus,
            CredentialStatus.permissionDenied,
            "wrong-PIN qualification"
        );
        report("wrong_pin_fail_closed=PASS");
    }

    mkdirRecurse(options.workDir);

    const stem =
        "credentials-d-fido2-qualification-" ~
        getpid().to!string;
    const vaultPath =
        buildPath(options.workDir, stem ~ ".vault");
    const envelopeAPath =
        buildPath(options.workDir, stem ~ ".a.envelope");
    const envelopeBPath =
        buildPath(options.workDir, stem ~ ".b.envelope");

    scope(exit)
    {
        if (exists(envelopeBPath))
            remove(envelopeBPath);
        if (exists(envelopeAPath))
            remove(envelopeAPath);
        if (exists(vaultPath ~ ".lock"))
            remove(vaultPath ~ ".lock");
        if (exists(vaultPath))
            remove(vaultPath);
    }

    enforce(!exists(vaultPath), "qualification vault path already exists");

    auto ns = namespaceOf(
        "org.alex1974.credentials-fido2-qualification"
    );

    auto passphrase = SecretBuffer(
        cast(const(ubyte)[])
            "synthetic-qualification-passphrase-v1"
    );

    EncryptedCredentialVault store;
    enforceStatus(
        EncryptedCredentialVault.createNew(
            vaultPath,
            ns,
            passphrase,
            store
        ),
        CredentialStatus.ok,
        "create synthetic qualification vault"
    );

    ubyte[] syntheticBytes = [
        0x46, 0x49, 0x44, 0x4f, 0x32,
        0x00,
        0x51, 0x55, 0x41, 0x4c,
        0xff, 0x01
    ];
    auto syntheticSecret = SecretBuffer(syntheticBytes);

    CredentialHandle handle;
    enforceStatus(
        store.save(syntheticSecret, handle),
        CredentialStatus.ok,
        "store synthetic credential"
    );
    enforce(handle.valid, "synthetic handle not returned");

    VaultUnlockMethod envelopeA;
    auto envelopeAStatus = addEnvelope(
        options,
        store,
        selectedDeviceA,
        pin,
        "Envelope A",
        envelopeA
    );

    if (!options.uv &&
        envelopeAStatus == CredentialStatus.interactionRequired &&
        pin.empty)
    {
        stderr.writeln(
            "creation_pin_required=YES (envelope credential enrollment)"
        );
        stderr.flush();
        pin = readPin();

        envelopeAStatus = addEnvelope(
            options,
            store,
            selectedDeviceA,
            pin,
            "Envelope A retry",
            envelopeA
        );
    }

    enforceStatus(
        envelopeAStatus,
        CredentialStatus.ok,
        "add FIDO2 envelope A"
    );

    const envelopeABytes = envelopeA.serialize();
    write(envelopeAPath, envelopeABytes);

    const persistedA =
        cast(ubyte[])read(envelopeAPath);
    VaultUnlockMethod parsedEnvelopeA;
    enforce(
        VaultUnlockMethod.tryParse(
            persistedA,
            parsedEnvelopeA
        ),
        "persisted envelope A did not parse"
    );

    store.lock();

    EncryptedCredentialVault reopened;
    enforceStatus(
        EncryptedCredentialVault.openExisting(
            vaultPath,
            ns,
            reopened
        ),
        CredentialStatus.ok,
        "reopen synthetic vault"
    );
    enforce(reopened.isLocked, "reopened vault unexpectedly unlocked");

    enforceStatus(
        unlockEnvelope(
            options,
            reopened,
            selectedDeviceA,
            parsedEnvelopeA,
            pin,
            "Unlock vault with envelope A."
        ),
        CredentialStatus.ok,
        "unlock with FIDO2 envelope A"
    );

    bool acquired;
    enforceStatus(
        reopened.withSecret(
            handle,
            (scope const(ubyte)[] bytes) @safe
            {
                enforce(
                    bytes == syntheticBytes,
                    "synthetic credential changed after FIDO2 reopen"
                );
                acquired = true;
            }
        ),
        CredentialStatus.ok,
        "read synthetic credential after FIDO2 unlock"
    );
    enforce(acquired, "synthetic credential visitor was not called");

    report("vault_reopen_fido2_unlock=PASS");
    report("binary_secret_roundtrip=PASS");

    reopened.lock();

    auto tampered = envelopeABytes.dup;
    enum size_t firstWrappedKeyByte =
        8 + 2 + 2 + 4 + 16 + 32 + 24;
    enforce(
        tampered.length > firstWrappedKeyByte,
        "envelope shorter than v1 wrapped-key offset"
    );
    tampered[firstWrappedKeyByte] ^= 0x01;

    VaultUnlockMethod tamperedEnvelope;
    enforce(
        VaultUnlockMethod.tryParse(
            tampered,
            tamperedEnvelope
        ),
        "tampered envelope should remain structurally parseable"
    );

    enforceStatus(
        unlockEnvelope(
            options,
            reopened,
            selectedDeviceA,
            tamperedEnvelope,
            pin,
            "Tampered-envelope rejection check."
        ),
        CredentialStatus.permissionDenied,
        "tampered FIDO2 envelope"
    );
    enforce(reopened.isLocked, "tampered envelope unlocked the vault");

    report("tampered_envelope_rejected=PASS");

    Fido2VaultBinding wrongCredentialBinding;
    enforceStatus(
        enroll(
            options,
            selectedDeviceA,
            pin,
            "Independent wrong-credential enrollment.",
            wrongCredentialBinding
        ),
        CredentialStatus.ok,
        "wrong-credential test enrollment"
    );

    const wrongCredentialEnvelope =
        withReplacementBinding(
            parsedEnvelopeA,
            wrongCredentialBinding
        );

    enforceStatus(
        unlockEnvelope(
            options,
            reopened,
            selectedDeviceA,
            wrongCredentialEnvelope,
            pin,
            "Wrong-credential rejection check."
        ),
        CredentialStatus.permissionDenied,
        "wrong FIDO2 credential"
    );
    enforce(
        reopened.isLocked,
        "wrong FIDO2 credential unlocked the vault"
    );
    report("wrong_credential_rejected=PASS");

    if (hasDeviceB)
    {
        const wrongDeviceStatus = unlockEnvelope(
            options,
            reopened,
            options.deviceB,
            parsedEnvelopeA,
            pin,
            "Wrong-authenticator rejection check on key B."
        );

        enforce(
            wrongDeviceStatus != CredentialStatus.ok,
            "security key B unlocked envelope A"
        );
        enforce(reopened.isLocked, "wrong authenticator unlocked the vault");

        report(
            "wrong_authenticator_rejected=PASS status=",
            cast(int)wrongDeviceStatus
        );
    }
    else
    {
        report("wrong_authenticator_rejected=SKIP_NO_SECOND_KEY");
    }

    enforceStatus(
        reopened.unlock(passphrase),
        CredentialStatus.ok,
        "passphrase recovery after FIDO2 failure"
    );
    report("passphrase_recovery=PASS");

    if (hasDeviceB)
    {
        VaultUnlockMethod envelopeB;
        enforceStatus(
            addEnvelope(
                options,
                reopened,
                options.deviceB,
                pin,
                "Envelope B",
                envelopeB
            ),
            CredentialStatus.ok,
            "add FIDO2 envelope B"
        );

        const envelopeBBytes = envelopeB.serialize();
        write(envelopeBPath, envelopeBBytes);

        const persistedB =
            cast(ubyte[])read(envelopeBPath);
        VaultUnlockMethod parsedEnvelopeB;
        enforce(
            VaultUnlockMethod.tryParse(
                persistedB,
                parsedEnvelopeB
            ),
            "persisted envelope B did not parse"
        );

        reopened.lock();

        if (options.confirmRemoveA)
            waitForRemoval(selectedDeviceA);

        enforceStatus(
            unlockEnvelope(
                options,
                reopened,
                options.deviceB,
                parsedEnvelopeB,
                pin,
                "Unlock vault with independent envelope B."
            ),
            CredentialStatus.ok,
            "unlock with independent FIDO2 envelope B"
        );

        bool backupAcquired;
        enforceStatus(
            reopened.withSecret(
                handle,
                (scope const(ubyte)[] bytes) @safe
                {
                    enforce(
                        bytes == syntheticBytes,
                        "backup-key unlock changed synthetic credential"
                    );
                    backupAcquired = true;
                }
            ),
            CredentialStatus.ok,
            "read after backup-key unlock"
        );
        enforce(backupAcquired, "backup-key visitor not called");

        report("backup_key_independent_unlock=PASS");
        report(
            "device_a_removed_check=",
            options.confirmRemoveA ? "PASS" : "SKIP"
        );
    }
    else
    {
        report("backup_key_independent_unlock=SKIP_NO_SECOND_KEY");
        report("device_a_removed_check=SKIP_NO_SECOND_KEY");
    }

    report("result=PASS");
}
