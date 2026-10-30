/**
 * Security regression tests for the in-memory encrypted-vault format.
 */
module credentials.backend.vault.security_tests;

import credentials.backend.vault.core;
import credentials.namespace : CredentialNamespace;
import credentials.secret : SecretBuffer;

private CredentialNamespace namespaceOf(string value)
{
    CredentialNamespace ns;
    assert(CredentialNamespace.tryParse(value, ns));
    return ns;
}

private void writeU16At(ref ubyte[] image, size_t offset, ushort value)
{
    assert(offset <= image.length && 2 <= image.length - offset);
    image[offset] = cast(ubyte)value;
    image[offset + 1] = cast(ubyte)(value >> 8);
}

private void writeU32At(ref ubyte[] image, size_t offset, uint value)
{
    assert(offset <= image.length && 4 <= image.length - offset);
    image[offset] = cast(ubyte)value;
    image[offset + 1] = cast(ubyte)(value >> 8);
    image[offset + 2] = cast(ubyte)(value >> 16);
    image[offset + 3] = cast(ubyte)(value >> 24);
}

private void writeU64At(ref ubyte[] image, size_t offset, ulong value)
{
    assert(offset <= image.length && 8 <= image.length - offset);

    foreach (i; 0 .. 8)
        image[offset + i] = cast(ubyte)(value >> (8 * i));
}

private bool containsBytes(
    scope const(ubyte)[] haystack,
    scope const(ubyte)[] needle
) @nogc nothrow @safe
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

@("vault image does not contain credential plaintext")
unittest
{
    auto ns = namespaceOf("org.example.vaultplaintext");
    auto passphrase =
        SecretBuffer(cast(const(ubyte)[]) "vault-test-passphrase");

    ubyte[] image;
    assert(createEmptyVaultImage(ns, passphrase, image) ==
        VaultCoreStatus.ok);

    enum string sentinel =
        "SENTINEL_CREDENTIAL_PLAINTEXT_7f2a1c9d";
    auto secret =
        SecretBuffer(cast(const(ubyte)[]) sentinel);

    string locator;
    assert(vaultPut(image, ns, passphrase, secret, locator) ==
        VaultCoreStatus.ok);

    assert(!containsBytes(
        image,
        cast(const(ubyte)[]) sentinel
    ));
}

@("hostile KDF cost is rejected by the parser")
unittest
{
    auto ns = namespaceOf("org.example.vaultkdf");
    auto passphrase =
        SecretBuffer(cast(const(ubyte)[]) "vault-test-passphrase");

    ubyte[] image;
    assert(createEmptyVaultImage(ns, passphrase, image) ==
        VaultCoreStatus.ok);

    auto secret = SecretBuffer(cast(const(ubyte)[]) "value");
    string locator;
    assert(vaultPut(image, ns, passphrase, secret, locator) ==
        VaultCoreStatus.ok);

    // Header offset 16 is the little-endian opslimit.
    auto hostile = image.dup;
    writeU32At(hostile, 16, uint.max);

    bool called;
    assert(vaultAcquire(
        hostile,
        ns,
        passphrase,
        locator,
        (scope const(ubyte)[]) @safe { called = true; }
    ) == VaultCoreStatus.corruptData);
    assert(!called);
}

@("wrapped key authentication fails closed")
unittest
{
    auto ns = namespaceOf("org.example.vaultwrap");
    auto passphrase =
        SecretBuffer(cast(const(ubyte)[]) "vault-test-passphrase");

    ubyte[] image;
    assert(createEmptyVaultImage(ns, passphrase, image) ==
        VaultCoreStatus.ok);

    auto secret = SecretBuffer(cast(const(ubyte)[]) "value");
    string locator;
    assert(vaultPut(image, ns, passphrase, secret, locator) ==
        VaultCoreStatus.ok);

    // Fixed v1 header: salt begins at 28 and wrapped key at 84.
    auto changedSalt = image.dup;
    changedSalt[28] ^= 1;

    bool called;
    assert(vaultAcquire(
        changedSalt,
        ns,
        passphrase,
        locator,
        (scope const(ubyte)[]) @safe { called = true; }
    ) == VaultCoreStatus.permissionDenied);
    assert(!called);

    auto changedWrappedKey = image.dup;
    changedWrappedKey[84] ^= 1;

    assert(vaultAcquire(
        changedWrappedKey,
        ns,
        passphrase,
        locator,
        (scope const(ubyte)[]) @safe { called = true; }
    ) == VaultCoreStatus.permissionDenied);
    assert(!called);
}

@("wrong namespace fails before secret exposure")
unittest
{
    auto ns = namespaceOf("org.example.vaultnamespace");
    auto other = namespaceOf("org.example.othernamespace");
    auto passphrase =
        SecretBuffer(cast(const(ubyte)[]) "vault-test-passphrase");

    ubyte[] image;
    assert(createEmptyVaultImage(ns, passphrase, image) ==
        VaultCoreStatus.ok);

    auto secret = SecretBuffer(cast(const(ubyte)[]) "value");
    string locator;
    assert(vaultPut(image, ns, passphrase, secret, locator) ==
        VaultCoreStatus.ok);

    bool called;
    assert(vaultAcquire(
        image,
        other,
        passphrase,
        locator,
        (scope const(ubyte)[]) @safe { called = true; }
    ) == VaultCoreStatus.invalidInput);
    assert(!called);
}

@("truncated vault images fail closed")
unittest
{
    auto ns = namespaceOf("org.example.vaulttruncate");
    auto passphrase =
        SecretBuffer(cast(const(ubyte)[]) "vault-test-passphrase");

    ubyte[] image;
    assert(createEmptyVaultImage(ns, passphrase, image) ==
        VaultCoreStatus.ok);

    auto secret = SecretBuffer(cast(const(ubyte)[]) "value");
    string locator;
    assert(vaultPut(image, ns, passphrase, secret, locator) ==
        VaultCoreStatus.ok);

    const size_t[] cuts = [
        0, 8, 16, 28, 60, 84, 164, image.length - 1
    ];

    foreach (cut; cuts)
    {
        assert(cut < image.length);
        bool called;

        assert(vaultAcquire(
            image[0 .. cut],
            ns,
            passphrase,
            locator,
            (scope const(ubyte)[]) @safe { called = true; }
        ) == VaultCoreStatus.corruptData);
        assert(!called);
    }
}

@("oversized credential is rejected before vault work")
unittest
{
    auto ns = namespaceOf("org.example.vaultoversize");
    auto passphrase =
        SecretBuffer(cast(const(ubyte)[]) "vault-test-passphrase");

    ubyte[] image;
    assert(createEmptyVaultImage(ns, passphrase, image) ==
        VaultCoreStatus.ok);

    // The v1 format limit is 64 KiB per credential.
    auto bytes = new ubyte[64 * 1024 + 1];
    auto oversized = SecretBuffer(bytes);

    string locator;
    assert(vaultPut(
        image,
        ns,
        passphrase,
        oversized,
        locator
    ) == VaultCoreStatus.tooLarge);
    assert(locator is null);
}


@("vault structural malformed-input corpus fails before KDF")
unittest
{
    auto ns = namespaceOf("org.example.vaultmalformed");
    auto passphrase =
        SecretBuffer(cast(const(ubyte)[]) "vault-test-passphrase");

    ubyte[] valid;
    assert(createEmptyVaultImage(ns, passphrase, valid) ==
        VaultCoreStatus.ok);
    assert(validateVaultImageHeader(valid, ns) ==
        VaultCoreStatus.ok);

    // Version-1 layout offsets. This test intentionally targets only fields
    // parsed and bounded before Argon2 or payload decryption is reachable.
    enum size_t headerBytes = 164;
    enum size_t versionOffset = 8;
    enum size_t namespaceLengthOffset = 10;
    enum size_t kdfOffset = 12;
    enum size_t reservedOffset = 14;
    enum size_t opsOffset = 16;
    enum size_t memOffset = 20;
    enum size_t payloadLengthOffset = 156;
    enum size_t namespaceOffset = 164;

    // Every cut through the fixed header must be rejected without crypto work.
    foreach (cut; 0 .. headerBytes + 1)
    {
        assert(validateVaultImageHeader(valid[0 .. cut], ns) ==
            VaultCoreStatus.corruptData);
    }

    // Every magic byte participates in the format identity.
    foreach (offset; 0 .. 8)
    {
        auto malformed = valid.dup;
        malformed[offset] ^= 0x01;
        assert(validateVaultImageHeader(malformed, ns) ==
            VaultCoreStatus.corruptData);
    }

    // Version, KDF identifier and reserved field are exact.
    foreach (ushort version_; [cast(ushort)0, cast(ushort)2, ushort.max])
    {
        auto malformed = valid.dup;
        writeU16At(malformed, versionOffset, version_);
        assert(validateVaultImageHeader(malformed, ns) ==
            VaultCoreStatus.corruptData);
    }

    foreach (ushort kdf; [cast(ushort)0, cast(ushort)2, ushort.max])
    {
        auto malformed = valid.dup;
        writeU16At(malformed, kdfOffset, kdf);
        assert(validateVaultImageHeader(malformed, ns) ==
            VaultCoreStatus.corruptData);
    }

    {
        auto malformed = valid.dup;
        writeU16At(malformed, reservedOffset, 1);
        assert(validateVaultImageHeader(malformed, ns) ==
            VaultCoreStatus.corruptData);
    }

    // Namespace lengths are bounded before namespace bytes are consumed.
    foreach (ushort length; [
        cast(ushort)0,
        cast(ushort)97,
        ushort.max
    ])
    {
        auto malformed = valid.dup;
        writeU16At(malformed, namespaceLengthOffset, length);
        assert(validateVaultImageHeader(malformed, ns) ==
            VaultCoreStatus.corruptData);
    }

    // Argon2 cost values are attacker-controlled file input and are bounded
    // before crypto_pwhash is reachable.
    foreach (uint ops; [0U, 11U, uint.max])
    {
        auto malformed = valid.dup;
        writeU32At(malformed, opsOffset, ops);
        assert(validateVaultImageHeader(malformed, ns) ==
            VaultCoreStatus.corruptData);
    }

    foreach (ulong memory; [
        0UL,
        8UL * 1024 * 1024 - 1,
        512UL * 1024 * 1024 + 1,
        ulong.max
    ])
    {
        auto malformed = valid.dup;
        writeU64At(malformed, memOffset, memory);
        assert(validateVaultImageHeader(malformed, ns) ==
            VaultCoreStatus.corruptData);
    }

    // Ciphertext length must include an AEAD tag and remain within the
    // format's bounded payload envelope.
    foreach (ulong length; [0UL, 15UL, ulong.max])
    {
        auto malformed = valid.dup;
        writeU64At(malformed, payloadLengthOffset, length);
        assert(validateVaultImageHeader(malformed, ns) ==
            VaultCoreStatus.corruptData);
    }

    // Namespace syntax itself is validated before any key derivation.
    {
        auto malformed = valid.dup;
        assert(namespaceOffset < malformed.length);
        malformed[namespaceOffset] = cast(ubyte)'/';
        assert(validateVaultImageHeader(malformed, ns) ==
            VaultCoreStatus.corruptData);
    }

    // A syntactically valid but different namespace is a binding mismatch,
    // not a credential candidate.
    {
        auto malformed = valid.dup;
        assert(namespaceOffset < malformed.length);
        malformed[namespaceOffset] =
            malformed[namespaceOffset] == cast(ubyte)'x'
                ? cast(ubyte)'y'
                : cast(ubyte)'x';
        assert(validateVaultImageHeader(malformed, ns) ==
            VaultCoreStatus.invalidInput);
    }

    // The format is canonical: authenticated image bytes may not be followed
    // by ignored trailing material.
    {
        auto malformed = valid.dup;
        malformed ~= cast(ubyte)0;
        assert(validateVaultImageHeader(malformed, ns) ==
            VaultCoreStatus.corruptData);
    }
}
