module app;

version (linux):

import core.sys.posix.unistd : getpid;
import core.volatile : volatileStore;
import credentials :
    CredentialHandle,
    CredentialNamespace,
    CredentialStatus,
    SecretBuffer;
import credentials.backend.fido2 :
    Fido2DeviceInfo,
    Fido2VaultBinding,
    Fido2VerificationPolicy,
    addFido2VaultUnlock,
    addFido2VaultUnlockWithPin,
    discoverFido2Devices,
    enrollFido2VaultBinding,
    enrollFido2VaultBindingWithPin,
    unlockVaultWithFido2,
    unlockVaultWithFido2WithPin,
    withFido2WrappingKey,
    withFido2WrappingKeyWithPin;
import credentials.backend.vault :
    EncryptedVaultCredentialStore,
    VaultUnlockEnvelope,
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
    writeln;

private enum string defaultRpId =
    "credentials-d.local";

private struct Options
{
    bool discoverOnly;
    bool uv;
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

    return options;
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
    writeln(
        "Enter authenticator PIN on stdin. The PIN is not printed or included in receipts."
    );

    auto line = stdin.readln();
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
    out Fido2VaultBinding binding
)
{
    const policy = options.uv
        ? Fido2VerificationPolicy.userVerificationRequired
        : Fido2VerificationPolicy.userPresence;

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

private CredentialStatus derive(
    const Options options,
    string devicePath,
    scope const Fido2VaultBinding binding,
    scope const ubyte[protectorSaltBytes] salt,
    scope ref const SecretBuffer pin,
    ref ubyte[32] output
)
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

private CredentialStatus addEnvelope(
    const Options options,
    EncryptedVaultCredentialStore store,
    string devicePath,
    scope ref const SecretBuffer pin,
    out VaultUnlockEnvelope envelope
)
{
    const policy = options.uv
        ? Fido2VerificationPolicy.userVerificationRequired
        : Fido2VerificationPolicy.userPresence;

    if (!pin.empty)
        return addFido2VaultUnlockWithPin(
            store,
            devicePath,
            options.rpId,
            policy,
            pin,
            envelope
        );

    return addFido2VaultUnlock(
        store,
        devicePath,
        options.rpId,
        policy,
        envelope
    );
}

private CredentialStatus unlockEnvelope(
    const Options options,
    EncryptedVaultCredentialStore store,
    string devicePath,
    scope const VaultUnlockEnvelope envelope,
    scope ref const SecretBuffer pin
)
{
    if (options.uv)
        return unlockVaultWithFido2WithPin(
            store,
            devicePath,
            envelope,
            pin
        );

    return unlockVaultWithFido2(
        store,
        devicePath,
        envelope
    );
}

private void printDevice(string label, scope const Fido2DeviceInfo device)
{
    writeln(label, "_manufacturer=", device.manufacturer);
    writeln(label, "_product=", device.product);
}

private bool findDevicePresent(
    scope const Fido2DeviceInfo[] devices,
    string path
) @safe
{
    Fido2DeviceInfo ignored;
    return findDevice(devices, path, ignored);
}

private void waitForRemoval(string deviceA)
{
    writeln(
        "ACTION_REQUIRED=Unplug security key A, then press Enter."
    );
    stdin.readln();

    const devices = discover();
    enforce(
        !findDevicePresent(devices, deviceA),
        "security key A is still discoverable after removal confirmation"
    );
}

void main(string[] args)
{
    const options = parseOptions(args);
    const devices = discover();

    writeln("qualification=fido2-hardware-v1");
    writeln("d_frontend=", __VERSION__);
    writeln("discovered_devices=", devices.length);

    if (options.discoverOnly)
    {
        foreach (i, ref const device; devices)
        {
            writeln("device_index=", i);
            writeln("device_path=", device.path);
            printDevice("device", device);
        }

        writeln("result=DISCOVERY_ONLY");
        return;
    }

    Fido2DeviceInfo deviceAInfo;
    string selectedDeviceA;
    enforce(
        selectPrimaryDevice(
            devices,
            selectedDeviceA,
            deviceAInfo,
            selectedDeviceA
        ),
        options.deviceA.length == 0 || options.deviceA == "auto"
            ? "automatic device selection requires exactly one discoverable FIDO2 device"
            : "device A is not currently discoverable"
    );

    writeln("device_a_path=", selectedDeviceA);

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

    writeln("policy=", options.uv ? "uv-required" : "user-presence");
    printDevice("device_a", deviceAInfo);
    if (hasDeviceB)
        printDevice("device_b", deviceBInfo);

    auto pin = options.uv
        ? readPin()
        : SecretBuffer.init;

    Fido2VaultBinding deterministicBinding;
    auto enrollmentStatus = enroll(
        options,
        selectedDeviceA,
        pin,
        deterministicBinding
    );

    if (!options.uv &&
        enrollmentStatus == CredentialStatus.interactionRequired &&
        pin.empty)
    {
        writeln(
            "creation_pin_required=YES (CTAP2 authenticator requires PIN for MakeCredential; later user-presence hmac-secret derivation remains PIN-less)"
        );
        pin = readPin();

        enrollmentStatus = enroll(
            options,
            selectedDeviceA,
            pin,
            deterministicBinding
        );
    }

    if (enrollmentStatus == CredentialStatus.unsupported)
    {
        writeln("result=UNSUPPORTED");
        writeln("unsupported_stage=enrollment-policy");
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

    writeln("hmac_same_salt=PASS");
    writeln("hmac_different_salt=PASS");
    writeln("device_path_not_persisted=PASS");

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
            wrongPinOutput
        );

        enforceStatus(
            wrongPinStatus,
            CredentialStatus.permissionDenied,
            "wrong-PIN qualification"
        );
        writeln("wrong_pin_fail_closed=PASS");
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

    EncryptedVaultCredentialStore store;
    enforceStatus(
        EncryptedVaultCredentialStore.createNew(
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
        store.store(syntheticSecret, handle),
        CredentialStatus.ok,
        "store synthetic credential"
    );
    enforce(handle.valid, "synthetic handle not returned");

    VaultUnlockEnvelope envelopeA;
    auto envelopeAStatus = addEnvelope(
        options,
        store,
        selectedDeviceA,
        pin,
        envelopeA
    );

    if (!options.uv &&
        envelopeAStatus == CredentialStatus.interactionRequired &&
        pin.empty)
    {
        writeln(
            "creation_pin_required=YES (envelope credential enrollment)"
        );
        pin = readPin();

        envelopeAStatus = addEnvelope(
            options,
            store,
            selectedDeviceA,
            pin,
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
    VaultUnlockEnvelope parsedEnvelopeA;
    enforce(
        VaultUnlockEnvelope.tryParse(
            persistedA,
            parsedEnvelopeA
        ),
        "persisted envelope A did not parse"
    );

    store.lock();

    EncryptedVaultCredentialStore reopened;
    enforceStatus(
        EncryptedVaultCredentialStore.openExisting(
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
            pin
        ),
        CredentialStatus.ok,
        "unlock with FIDO2 envelope A"
    );

    bool acquired;
    enforceStatus(
        reopened.acquire(
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

    writeln("vault_reopen_fido2_unlock=PASS");
    writeln("binary_secret_roundtrip=PASS");

    reopened.lock();

    auto tampered = envelopeABytes.dup;
    enum size_t firstWrappedKeyByte =
        8 + 2 + 2 + 4 + 16 + 32 + 24;
    enforce(
        tampered.length > firstWrappedKeyByte,
        "envelope shorter than v1 wrapped-key offset"
    );
    tampered[firstWrappedKeyByte] ^= 0x01;

    VaultUnlockEnvelope tamperedEnvelope;
    enforce(
        VaultUnlockEnvelope.tryParse(
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
            pin
        ),
        CredentialStatus.permissionDenied,
        "tampered FIDO2 envelope"
    );
    enforce(reopened.isLocked, "tampered envelope unlocked the vault");

    writeln("tampered_envelope_rejected=PASS");

    if (hasDeviceB)
    {
        const wrongDeviceStatus = unlockEnvelope(
            options,
            reopened,
            options.deviceB,
            parsedEnvelopeA,
            pin
        );

        enforce(
            wrongDeviceStatus != CredentialStatus.ok,
            "security key B unlocked envelope A"
        );
        enforce(reopened.isLocked, "wrong authenticator unlocked the vault");

        writeln(
            "wrong_authenticator_rejected=PASS status=",
            cast(int)wrongDeviceStatus
        );
    }
    else
    {
        writeln("wrong_authenticator_rejected=SKIP_NO_SECOND_KEY");
    }

    enforceStatus(
        reopened.unlock(passphrase),
        CredentialStatus.ok,
        "passphrase recovery after FIDO2 failure"
    );
    writeln("passphrase_recovery=PASS");

    if (hasDeviceB)
    {
        VaultUnlockEnvelope envelopeB;
        enforceStatus(
            addEnvelope(
                options,
                reopened,
                options.deviceB,
                pin,
                envelopeB
            ),
            CredentialStatus.ok,
            "add FIDO2 envelope B"
        );

        const envelopeBBytes = envelopeB.serialize();
        write(envelopeBPath, envelopeBBytes);

        const persistedB =
            cast(ubyte[])read(envelopeBPath);
        VaultUnlockEnvelope parsedEnvelopeB;
        enforce(
            VaultUnlockEnvelope.tryParse(
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
                pin
            ),
            CredentialStatus.ok,
            "unlock with independent FIDO2 envelope B"
        );

        bool backupAcquired;
        enforceStatus(
            reopened.acquire(
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

        writeln("backup_key_independent_unlock=PASS");
        writeln(
            "device_a_removed_check=",
            options.confirmRemoveA ? "PASS" : "SKIP"
        );
    }
    else
    {
        writeln("backup_key_independent_unlock=SKIP_NO_SECOND_KEY");
        writeln("device_a_removed_check=SKIP_NO_SECOND_KEY");
    }

    writeln("result=PASS");
}
