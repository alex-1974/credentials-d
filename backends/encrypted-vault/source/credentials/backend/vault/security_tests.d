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

private void writeU32At(ref ubyte[] image, size_t offset, uint value)
{
    assert(offset <= image.length && 4 <= image.length - offset);
    image[offset] = cast(ubyte)value;
    image[offset + 1] = cast(ubyte)(value >> 8);
    image[offset + 2] = cast(ubyte)(value >> 16);
    image[offset + 3] = cast(ubyte)(value >> 24);
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
