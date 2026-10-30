/**
 * Persistable non-secret FIDO2 vault-protector binding.
 */
module credentials.backend.fido2.binding;

enum string fido2ProtectorKind = "fido2-hmac-secret";
enum size_t maximumCredentialIdBytes = 1024;
enum size_t maximumRpIdBytes = 253;

/**
 * User-interaction policy used consistently at enrollment and unlock.
 */
enum Fido2VerificationPolicy : ubyte
{
    userPresence = 1,
    userVerificationRequired = 2
}

private enum ubyte[8] bindingMagic =
    ['F','I','D','O','V','L','T','1'];
private enum ushort bindingVersion = 1;
private enum size_t fixedBindingBytes =
    bindingMagic.length + 2 + 1 + 1 + 2 + 2;

/**
 * Non-secret data needed to reproduce one credential-scoped hmac-secret.
 *
 * Device paths are deliberately excluded: they are ephemeral runtime
 * identifiers and must not be persisted as security identity.
 */
struct Fido2VaultBinding
{
    private string rpId_;
    private ubyte[] credentialId_;
    private Fido2VerificationPolicy policy_;

    @property string rpId() const @nogc nothrow @safe
    {
        return rpId_;
    }

    @property const(ubyte)[] credentialId() const scope
        @nogc nothrow @safe
    {
        return credentialId_;
    }

    @property Fido2VerificationPolicy verificationPolicy() const
        @nogc nothrow @safe
    {
        return policy_;
    }

    @property bool valid() const scope @nogc nothrow @safe
    {
        return validRpId(rpId_) &&
            credentialId_.length != 0 &&
            credentialId_.length <= maximumCredentialIdBytes &&
            validPolicy(policy_);
    }

    /**
     * Serialize the binding for inclusion in a VaultUnlockEnvelope.
     */
    ubyte[] serialize() const @safe
    in (valid)
    {
        const total =
            fixedBindingBytes +
            rpId_.length +
            credentialId_.length;

        auto output = new ubyte[total];
        size_t pos;

        put(output, pos, bindingMagic[]);
        putU16(output, pos, bindingVersion);
        output[pos++] = cast(ubyte)policy_;
        output[pos++] = 0;
        putU16(output, pos, cast(ushort)rpId_.length);
        putU16(output, pos, cast(ushort)credentialId_.length);

        foreach (char c; rpId_)
            output[pos++] = cast(ubyte)c;

        output[pos .. pos + credentialId_.length] =
            credentialId_[];
        pos += credentialId_.length;

        assert(pos == output.length);
        return output;
    }

    /**
     * Parse a canonical bounded binding.
     */
    static bool tryParse(
        scope const(ubyte)[] input,
        out Fido2VaultBinding binding
    ) @safe
    {
        binding = Fido2VaultBinding.init;

        if (input.length < fixedBindingBytes)
            return false;

        size_t pos;

        if (!takeEquals(input, pos, bindingMagic[]))
            return false;

        ushort version_;
        if (!takeU16(input, pos, version_))
            return false;

        if (version_ != bindingVersion ||
            pos + 2 > input.length)
            return false;

        const policy =
            cast(Fido2VerificationPolicy)input[pos++];
        const reserved = input[pos++];

        ushort rpLength;
        ushort credentialLength;

        if (!takeU16(input, pos, rpLength) ||
            !takeU16(input, pos, credentialLength))
            return false;

        if (reserved != 0 ||
            !validPolicy(policy) ||
            rpLength == 0 ||
            rpLength > maximumRpIdBytes ||
            credentialLength == 0 ||
            credentialLength > maximumCredentialIdBytes)
            return false;

        const variable =
            cast(size_t)rpLength +
            cast(size_t)credentialLength;

        if (pos > input.length ||
            variable != input.length - pos)
            return false;

        const rpBytes =
            input[pos .. pos + cast(size_t)rpLength];

        if (!validRpIdBytes(rpBytes))
            return false;

        char[] rpChars = new char[rpBytes.length];
        foreach (i, value; rpBytes)
            rpChars[i] = cast(char)value;

        pos += rpLength;

        binding.rpId_ = rpChars.idup;
        binding.credentialId_ =
            input[pos .. pos + cast(size_t)credentialLength].dup;
        binding.policy_ = policy;

        return binding.valid;
    }

    package(credentials.backend.fido2) static Fido2VaultBinding trusted(
        string rpId,
        scope const(ubyte)[] credentialId,
        Fido2VerificationPolicy policy
    ) @safe
    {
        Fido2VaultBinding binding;
        binding.rpId_ = rpId;
        binding.credentialId_ = credentialId.dup;
        binding.policy_ = policy;
        return binding;
    }
}

package(credentials.backend.fido2) bool validRpId(string value)
    @nogc nothrow pure @safe
{
    if (value.length == 0 || value.length > maximumRpIdBytes)
        return false;

    return validRpIdBytes(cast(const(ubyte)[])value);
}

private bool validRpIdBytes(scope const(ubyte)[] value)
    @nogc nothrow pure @safe
{
    if (value.length == 0 || value.length > maximumRpIdBytes)
        return false;

    bool segmentStart = true;
    bool previousHyphen;

    foreach (ubyte c; value)
    {
        if (c == '.')
        {
            if (segmentStart || previousHyphen)
                return false;
            segmentStart = true;
            previousHyphen = false;
            continue;
        }

        const alnum =
            (c >= 'a' && c <= 'z') ||
            (c >= '0' && c <= '9');

        if (alnum)
        {
            segmentStart = false;
            previousHyphen = false;
            continue;
        }

        if (c == '-')
        {
            if (segmentStart)
                return false;
            previousHyphen = true;
            continue;
        }

        return false;
    }

    return !segmentStart && !previousHyphen;
}

private bool validPolicy(Fido2VerificationPolicy policy)
    @nogc nothrow pure @safe
{
    return
        policy == Fido2VerificationPolicy.userPresence ||
        policy ==
            Fido2VerificationPolicy.userVerificationRequired;
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

@("FIDO2 vault binding round-trips")
unittest
{
    ubyte[] credential = [1, 2, 3, 4, 0, 255];

    auto original = Fido2VaultBinding.trusted(
        "credentials-d.local",
        credential,
        Fido2VerificationPolicy.userVerificationRequired
    );

    const encoded = original.serialize();

    Fido2VaultBinding parsed;
    assert(Fido2VaultBinding.tryParse(encoded, parsed));
    assert(parsed.rpId == original.rpId);
    assert(parsed.credentialId == credential);
    assert(
        parsed.verificationPolicy ==
        Fido2VerificationPolicy.userVerificationRequired
    );
}

@("FIDO2 binding rejects malformed and unsafe RP ids")
unittest
{
    Fido2VaultBinding binding;

    assert(!Fido2VaultBinding.tryParse([], binding));
    assert(!validRpId("Credentials-D.local"));
    assert(!validRpId(".credentials-d.local"));
    assert(!validRpId("credentials-d..local"));
    assert(!validRpId("credentials-d.local-"));
    assert(!validRpId("credentials_d.local"));
}
