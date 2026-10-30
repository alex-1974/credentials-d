/**
 * External vault-key protector envelopes.
 *
 * A protector envelope is non-secret metadata plus an authenticated wrapping
 * of the random vault key. It may be persisted independently of the vault.
 */
module credentials.backend.vault.protector;

import credentials.backend.vault.sodium :
    aeadTagBytes,
    crypto_aead_xchacha20poly1305_ietf_decrypt,
    crypto_aead_xchacha20poly1305_ietf_encrypt,
    sodiumReady,
    vaultKeyBytes,
    xNonceBytes,
    zeroFixed;
import credentials.namespace : CredentialNamespace;
import credentials.random : secureRandomBytes;
import credentials.store :
    CredentialStatus,
    SecretVisitor;

enum size_t protectorSaltBytes = 32;
enum size_t maximumProtectorKindBytes = 32;
enum size_t maximumProtectorBindingBytes = 4096;

/**
 * Produce a 32-byte wrapping key for one random protector salt.
 *
 * The implementation may interact with hardware or the user. It must invoke
 * visitor exactly once on CredentialStatus.ok and never on any other status.
 */
alias VaultWrappingKeySource = CredentialStatus delegate(
    scope const ubyte[protectorSaltBytes] salt,
    scope SecretVisitor visitor
) @safe;

private enum ubyte[8] envelopeMagic =
    ['C','R','E','D','K','E','Y','1'];
private enum ushort envelopeVersion = 1;
private enum size_t wrappedVaultKeyBytes =
    vaultKeyBytes + aeadTagBytes;
private enum size_t fixedEnvelopeBytes =
    envelopeMagic.length + 2 + 2 + 4 +
    16 + protectorSaltBytes + xNonceBytes +
    wrappedVaultKeyBytes;

/**
 * Persistable non-secret unlock descriptor.
 *
 * The envelope binds one external protector to one vault id, namespace and
 * opaque protector binding. Tampering is detected by the vault-key AEAD.
 */
struct VaultUnlockEnvelope
{
    private string kind_;
    private ubyte[] binding_;
    private ubyte[16] vaultId_;
    private ubyte[protectorSaltBytes] salt_;
    private ubyte[xNonceBytes] nonce_;
    private ubyte[wrappedVaultKeyBytes] wrappedKey_;

    @property string protectorKind() const @nogc nothrow @safe
    {
        return kind_;
    }

    @property const(ubyte)[] protectorBinding() const scope
        @nogc nothrow @safe
    {
        return binding_;
    }

    @property bool valid() const scope @nogc nothrow @safe
    {
        return validKind(kind_) &&
            binding_.length <= maximumProtectorBindingBytes;
    }

    /**
     * Serialize the non-secret envelope for persistence.
     */
    ubyte[] serialize() const @safe
    in (valid)
    {
        const total =
            fixedEnvelopeBytes +
            kind_.length +
            binding_.length;

        auto output = new ubyte[total];
        size_t pos;

        put(output, pos, envelopeMagic[]);
        putU16(output, pos, envelopeVersion);
        putU16(output, pos, cast(ushort) kind_.length);
        putU32(output, pos, cast(uint) binding_.length);
        put(output, pos, vaultId_[]);
        put(output, pos, salt_[]);
        put(output, pos, nonce_[]);
        put(output, pos, wrappedKey_[]);
        putAscii(output, pos, kind_);
        put(output, pos, binding_);

        assert(pos == output.length);
        return output;
    }

    /**
     * Parse one bounded canonical envelope.
     */
    static bool tryParse(
        scope const(ubyte)[] input,
        out VaultUnlockEnvelope envelope
    ) @safe
    {
        envelope = VaultUnlockEnvelope.init;

        if (input.length < fixedEnvelopeBytes)
            return false;

        size_t pos;

        if (!takeEquals(input, pos, envelopeMagic[]))
            return false;

        ushort version_;
        ushort kindLength;
        uint bindingLength;

        if (!takeU16(input, pos, version_) ||
            !takeU16(input, pos, kindLength) ||
            !takeU32(input, pos, bindingLength))
            return false;

        if (version_ != envelopeVersion ||
            kindLength == 0 ||
            kindLength > maximumProtectorKindBytes ||
            bindingLength > maximumProtectorBindingBytes)
            return false;

        const variable =
            cast(size_t) kindLength +
            cast(size_t) bindingLength;

        if (pos > input.length ||
            fixedEnvelopeBytes - (envelopeMagic.length + 2 + 2 + 4) >
                input.length - pos ||
            variable >
                input.length -
                pos -
                (fixedEnvelopeBytes -
                    (envelopeMagic.length + 2 + 2 + 4)))
            return false;

        if (!takeFixed(input, pos, envelope.vaultId_) ||
            !takeFixed(input, pos, envelope.salt_) ||
            !takeFixed(input, pos, envelope.nonce_) ||
            !takeFixed(input, pos, envelope.wrappedKey_))
            return false;

        if (cast(size_t)kindLength > input.length - pos)
            return false;

        const kindBytes =
            input[pos .. pos + cast(size_t)kindLength];
        pos += kindLength;

        if (!validKindBytes(kindBytes))
            return false;

        char[] kindChars = new char[kindBytes.length];
        foreach (i, value; kindBytes)
            kindChars[i] = cast(char)value;
        envelope.kind_ = cast(string) kindChars;

        if (cast(size_t)bindingLength > input.length - pos)
            return false;

        envelope.binding_ =
            input[pos .. pos + cast(size_t)bindingLength].dup;
        pos += bindingLength;

        return pos == input.length && envelope.valid;
    }
}

/**
 * Consumer invoked only after a protector envelope has authenticated and
 * recovered one 256-bit vault key.
 */
alias RecoveredVaultKeyConsumer = CredentialStatus delegate(
    scope const(ubyte)[] vaultKey
) @safe;

/**
 * Create an additional external-protector wrapper for one random vault key.
 *
 * The envelope is independent of the persistence backend. Multiple independent
 * envelopes may be retained for one vault.
 */
CredentialStatus createVaultUnlockEnvelope(
    CredentialNamespace ns,
    scope const ubyte[16] vaultId,
    scope const(ubyte)[] vaultKey,
    string protectorKind,
    scope const(ubyte)[] protectorBinding,
    scope VaultWrappingKeySource keySource,
    out VaultUnlockEnvelope envelope
) @safe
{
    envelope = VaultUnlockEnvelope.init;

    if (!ns.valid ||
        vaultKey.length != vaultKeyBytes ||
        keySource is null ||
        !validKind(protectorKind) ||
        protectorBinding.length > maximumProtectorBindingBytes)
        return CredentialStatus.invalidInput;

    ubyte[protectorSaltBytes] salt;
    ubyte[xNonceBytes] nonce;

    if (!secureRandomBytes(salt[]) ||
        !secureRandomBytes(nonce[]))
        return CredentialStatus.backendFailure;

    auto bindingCopy = protectorBinding.dup;
    auto ad = buildEnvelopeAd(
        ns,
        protectorKind,
        bindingCopy,
        vaultId,
        salt
    );

    ubyte[wrappedVaultKeyBytes] wrapped;
    CredentialStatus sourceStatus = CredentialStatus.backendFailure;
    bool visitorCalled;

    sourceStatus = keySource(
        salt,
        (scope const(ubyte)[] wrappingKey) @safe
        {
            visitorCalled = true;

            if (wrappingKey.length != vaultKeyBytes)
            {
                sourceStatus = CredentialStatus.invalidInput;
                return;
            }

            if (!sodiumReady())
            {
                sourceStatus = CredentialStatus.unavailable;
                return;
            }

            ulong cipherLength;
            const rc =
                crypto_aead_xchacha20poly1305_ietf_encrypt(
                    wrapped.ptr,
                    &cipherLength,
                    vaultKey.ptr,
                    vaultKey.length,
                    ad.ptr,
                    ad.length,
                    null,
                    nonce.ptr,
                    wrappingKey.ptr
                );

            sourceStatus =
                rc == 0 && cipherLength == wrapped.length
                    ? CredentialStatus.ok
                    : CredentialStatus.backendFailure;
        }
    );

    if (sourceStatus != CredentialStatus.ok)
        return sourceStatus;

    if (!visitorCalled)
        return CredentialStatus.backendFailure;

    envelope.kind_ = protectorKind;
    envelope.binding_ = bindingCopy;
    envelope.vaultId_ = vaultId;
    envelope.salt_ = salt;
    envelope.nonce_ = nonce;
    envelope.wrappedKey_ = wrapped;

    return CredentialStatus.ok;
}

/**
 * Recover a vault key through an external protector envelope.
 *
 * The consumer sees the key only after the wrapper AEAD authenticates. A
 * persistence backend must still authenticate the actual vault payload before
 * accepting the key as an unlocked session.
 */
CredentialStatus recoverVaultKeyFromEnvelope(
    CredentialNamespace ns,
    scope const ubyte[16] currentVaultId,
    scope const VaultUnlockEnvelope envelope,
    scope VaultWrappingKeySource keySource,
    scope RecoveredVaultKeyConsumer consumer
) @safe
{
    if (!ns.valid ||
        keySource is null ||
        consumer is null ||
        !envelope.valid)
        return CredentialStatus.invalidInput;

    if (currentVaultId != envelope.vaultId_)
        return CredentialStatus.invalidInput;

    auto ad = buildEnvelopeAd(
        ns,
        envelope.kind_,
        envelope.binding_,
        envelope.vaultId_,
        envelope.salt_
    );

    ubyte[vaultKeyBytes] vaultKey;
    scope(exit) zeroFixed(vaultKey);

    CredentialStatus sourceStatus = CredentialStatus.backendFailure;
    bool visitorCalled;

    sourceStatus = keySource(
        envelope.salt_,
        (scope const(ubyte)[] wrappingKey) @safe
        {
            visitorCalled = true;

            if (wrappingKey.length != vaultKeyBytes)
            {
                sourceStatus = CredentialStatus.invalidInput;
                return;
            }

            if (!sodiumReady())
            {
                sourceStatus = CredentialStatus.unavailable;
                return;
            }

            ulong plaintextLength;
            const rc =
                crypto_aead_xchacha20poly1305_ietf_decrypt(
                    vaultKey.ptr,
                    &plaintextLength,
                    null,
                    envelope.wrappedKey_.ptr,
                    envelope.wrappedKey_.length,
                    ad.ptr,
                    ad.length,
                    envelope.nonce_.ptr,
                    wrappingKey.ptr
                );

            sourceStatus =
                rc == 0 && plaintextLength == vaultKey.length
                    ? CredentialStatus.ok
                    : CredentialStatus.permissionDenied;
        }
    );

    if (sourceStatus != CredentialStatus.ok)
        return sourceStatus;

    if (!visitorCalled)
        return CredentialStatus.backendFailure;

    return consumer(vaultKey[]);
}

private ubyte[] buildEnvelopeAd(
    CredentialNamespace ns,
    string kind,
    scope const(ubyte)[] binding,
    scope const ubyte[16] vaultId,
    scope const ubyte[protectorSaltBytes] salt
) @safe
{
    enum string domain =
        "credentials-d:vault-key-protector:v1";

    const nsText = ns.serialize();
    const total =
        domain.length +
        2 + nsText.length +
        2 + kind.length +
        4 + binding.length +
        vaultId.length +
        salt.length;

    auto output = new ubyte[total];
    size_t pos;

    putAscii(output, pos, domain);
    putU16(output, pos, cast(ushort)nsText.length);
    putAscii(output, pos, nsText);
    putU16(output, pos, cast(ushort)kind.length);
    putAscii(output, pos, kind);
    putU32(output, pos, cast(uint)binding.length);
    put(output, pos, binding);
    put(output, pos, vaultId[]);
    put(output, pos, salt[]);

    assert(pos == output.length);
    return output;
}

private bool validKind(string value) @nogc nothrow pure @safe
{
    if (value.length == 0 ||
        value.length > maximumProtectorKindBytes)
        return false;

    return validKindBytes(cast(const(ubyte)[])value);
}

private bool validKindBytes(scope const(ubyte)[] value)
    @nogc nothrow pure @safe
{
    if (value.length == 0 ||
        value.length > maximumProtectorKindBytes)
        return false;

    foreach (ubyte c; value)
    {
        const valid =
            (c >= 'a' && c <= 'z') ||
            (c >= '0' && c <= '9') ||
            c == '-';

        if (!valid)
            return false;
    }

    return true;
}

private void put(
    scope ubyte[] output,
    ref size_t pos,
    scope const(ubyte)[] value
) @safe
{
    assert(pos <= output.length);
    assert(value.length <= output.length - pos);
    output[pos .. pos + value.length] = value[];
    pos += value.length;
}

private void putAscii(
    scope ubyte[] output,
    ref size_t pos,
    string value
) @safe
{
    assert(pos <= output.length);
    assert(value.length <= output.length - pos);

    foreach (char c; value)
        output[pos++] = cast(ubyte)c;
}

private void putU16(
    scope ubyte[] output,
    ref size_t pos,
    ushort value
) @safe
{
    ubyte[2] bytes = [
        cast(ubyte)value,
        cast(ubyte)(value >> 8)
    ];
    put(output, pos, bytes[]);
}

private void putU32(
    scope ubyte[] output,
    ref size_t pos,
    uint value
) @safe
{
    ubyte[4] bytes = [
        cast(ubyte)value,
        cast(ubyte)(value >> 8),
        cast(ubyte)(value >> 16),
        cast(ubyte)(value >> 24)
    ];
    put(output, pos, bytes[]);
}

private bool takeEquals(
    scope const(ubyte)[] input,
    ref size_t pos,
    scope const(ubyte)[] expected
) @safe
{
    if (pos > input.length ||
        expected.length > input.length - pos)
        return false;

    foreach (i, value; expected)
        if (input[pos + i] != value)
            return false;

    pos += expected.length;
    return true;
}

private bool takeU16(
    scope const(ubyte)[] input,
    ref size_t pos,
    out ushort value
) @safe
{
    value = 0;

    if (pos > input.length || 2 > input.length - pos)
        return false;

    value =
        cast(ushort)input[pos] |
        cast(ushort)(cast(ushort)input[pos + 1] << 8);
    pos += 2;
    return true;
}

private bool takeU32(
    scope const(ubyte)[] input,
    ref size_t pos,
    out uint value
) @safe
{
    value = 0;

    if (pos > input.length || 4 > input.length - pos)
        return false;

    value =
        cast(uint)input[pos] |
        (cast(uint)input[pos + 1] << 8) |
        (cast(uint)input[pos + 2] << 16) |
        (cast(uint)input[pos + 3] << 24);
    pos += 4;
    return true;
}

private bool takeFixed(size_t N)(
    scope const(ubyte)[] input,
    ref size_t pos,
    ref ubyte[N] output
) @safe
{
    if (pos > input.length || N > input.length - pos)
        return false;

    output[] = input[pos .. pos + N];
    pos += N;
    return true;
}

@("protector envelope parser rejects malformed input")
unittest
{
    VaultUnlockEnvelope envelope;

    assert(!VaultUnlockEnvelope.tryParse([], envelope));
    assert(!VaultUnlockEnvelope.tryParse(
        cast(const(ubyte)[])"CREDKEY1",
        envelope
    ));
}
