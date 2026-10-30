/**
 * Bounded in-memory encrypted-vault format and cryptographic core.
 *
 * No filesystem persistence lives in this module.
 */
module credentials.backend.vault.core;

import credentials.backend.vault.sodium;
import credentials.backend.vault.session : VaultSession;
import credentials.namespace : CredentialNamespace;
import credentials.secret : SecretBuffer;
import credentials.store : SecretVisitor;

enum VaultCoreStatus
{
    ok,
    notFound,
    locked,
    unavailable,
    permissionDenied,
    tooLarge,
    corruptData,
    invalidInput,
    backendFailure
}

private:
enum ushort formatVersion = 1;
enum ushort kdfArgon2id = 1;
enum uint defaultOps = 3;
enum ulong defaultMemBytes = 64UL * 1024 * 1024;
enum uint minOps = 1;
enum uint maxOps = 10;
enum ulong minMemBytes = 8UL * 1024 * 1024;
enum ulong maxMemBytes = 512UL * 1024 * 1024;
enum size_t maxRecords = 4096;
enum size_t maxSecretBytes = 64 * 1024;
enum size_t maxPayloadBytes = 16 * 1024 * 1024;
enum size_t fixedHeaderBytes =
    8 + 2 + 2 + 2 + 2 + 4 + 8 +
    pwhashSaltBytes + 16 + xNonceBytes +
    (vaultKeyBytes + aeadTagBytes) +
    xNonceBytes + 8;

enum ubyte[8] vaultMagic =
    ['C','R','E','D','V','L','T','1'];
enum ubyte[4] payloadMagic = ['P','L','D','1'];

struct HeaderView
{
    uint ops;
    ulong memBytes;
    ubyte[pwhashSaltBytes] salt;
    ubyte[16] vaultId;
    ubyte[xNonceBytes] wrapNonce;
    ubyte[vaultKeyBytes + aeadTagBytes] wrappedKey;
    ubyte[xNonceBytes] payloadNonce;
    size_t payloadCipherOffset;
    size_t payloadCipherLength;
}

struct RecordView
{
    ubyte[16] id;
    size_t secretOffset;
    size_t secretLength;
}

struct Reader
{
    const(ubyte)[] data;
    size_t pos;

    bool canRead(size_t count) const scope
        @nogc nothrow pure @safe
    {
        return pos <= data.length && count <= data.length - pos;
    }

    bool skip(size_t count) scope
        @nogc nothrow @safe
    {
        if (!canRead(count))
            return false;

        pos += count;
        return true;
    }

    bool expect(scope const(ubyte)[] expected) scope
        @nogc nothrow @safe
    {
        if (!canRead(expected.length))
            return false;

        foreach (i, value; expected)
            if (data[pos + i] != value)
                return false;

        pos += expected.length;
        return true;
    }

    bool readFixed(size_t N)(ref ubyte[N] destination) scope
        @nogc nothrow @safe
    {
        if (!canRead(N))
            return false;

        foreach (i; 0 .. N)
            destination[i] = data[pos + i];

        pos += N;
        return true;
    }

    bool readNamespace(
        size_t count,
        string expected,
        out bool matches
    ) scope @nogc nothrow @safe
    {
        matches = false;

        if (!canRead(count))
            return false;

        if (count == 0 || count > 96)
            return false;

        bool segmentStart = true;
        bool previousHyphen;

        foreach (i; 0 .. count)
        {
            const c = data[pos + i];

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

        if (segmentStart || previousHyphen)
            return false;

        matches = count == expected.length;

        if (matches)
        {
            foreach (i, char ch; expected)
            {
                if (data[pos + i] != cast(ubyte) ch)
                {
                    matches = false;
                    break;
                }
            }
        }

        pos += count;
        return true;
    }

    bool readU16(out ushort value) scope
        @nogc nothrow @safe
    {
        value = 0;
        if (!canRead(2))
            return false;

        value = cast(ushort)(
            cast(ushort)data[pos] |
            (cast(ushort)data[pos + 1] << 8)
        );
        pos += 2;
        return true;
    }

    bool readU32(out uint value) scope
        @nogc nothrow @safe
    {
        value = 0;
        if (!canRead(4))
            return false;

        value =
            cast(uint)data[pos] |
            (cast(uint)data[pos + 1] << 8) |
            (cast(uint)data[pos + 2] << 16) |
            (cast(uint)data[pos + 3] << 24);
        pos += 4;
        return true;
    }

    bool readU64(out ulong value) scope
        @nogc nothrow @safe
    {
        value = 0;
        if (!canRead(8))
            return false;

        foreach (i; 0 .. 8)
            value |= cast(ulong)data[pos + i] << (8 * i);

        pos += 8;
        return true;
    }
}

struct Writer
{
    ubyte[] data;
    size_t pos;

    bool put(scope const(ubyte)[] bytes) @safe
    {
        if (pos > data.length || bytes.length > data.length - pos)
            return false;
        data[pos .. pos + bytes.length] = bytes[];
        pos += bytes.length;
        return true;
    }

    bool putAscii(string text) @safe
    {
        if (pos > data.length || text.length > data.length - pos)
            return false;

        foreach (char ch; text)
            data[pos++] = cast(ubyte) ch;

        return true;
    }

    bool putU16(ushort value) @safe
    {
        ubyte[2] b = [
            cast(ubyte)value,
            cast(ubyte)(value >> 8)
        ];
        return put(b[]);
    }

    bool putU32(uint value) @safe
    {
        ubyte[4] b = [
            cast(ubyte)value,
            cast(ubyte)(value >> 8),
            cast(ubyte)(value >> 16),
            cast(ubyte)(value >> 24)
        ];
        return put(b[]);
    }

    bool putU64(ulong value) @safe
    {
        ubyte[8] b;
        foreach (i; 0 .. 8)
            b[i] = cast(ubyte)(value >> (8 * i));
        return put(b[]);
    }
}

bool validNamespaceBytes(scope const(ubyte)[] text)
    @nogc nothrow @safe
{
    if (text.length == 0 || text.length > 96)
        return false;

    bool segmentStart = true;
    bool previousHyphen;

    foreach (ubyte c; text)
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

bool validKdf(uint ops, ulong memBytes) @nogc nothrow @safe
{
    if (ops < minOps || ops > maxOps)
        return false;
    if (memBytes < minMemBytes || memBytes > maxMemBytes)
        return false;
    if (memBytes > size_t.max)
        return false;
    return true;
}

VaultCoreStatus parseHeader(
    scope const(ubyte)[] image,
    CredentialNamespace expectedNamespace,
    out HeaderView header
) @safe
{
    header = HeaderView.init;

    if (!expectedNamespace.valid)
        return VaultCoreStatus.invalidInput;

    if (image.length < fixedHeaderBytes + 1 + aeadTagBytes)
        return VaultCoreStatus.corruptData;

    Reader r = Reader(image, 0);

    if (!r.expect(vaultMagic[]))
        return VaultCoreStatus.corruptData;

    ushort version_;
    ushort namespaceLength;
    ushort kdf;
    ushort reserved;

    if (!r.readU16(version_) ||
        !r.readU16(namespaceLength) ||
        !r.readU16(kdf) ||
        !r.readU16(reserved) ||
        !r.readU32(header.ops) ||
        !r.readU64(header.memBytes))
        return VaultCoreStatus.corruptData;

    if (version_ != formatVersion ||
        kdf != kdfArgon2id ||
        reserved != 0)
        return VaultCoreStatus.corruptData;

    // Hostile KDF parameters are rejected before any Argon2 invocation.
    if (!validKdf(header.ops, header.memBytes))
        return VaultCoreStatus.corruptData;

    if (!r.readFixed(header.salt) ||
        !r.readFixed(header.vaultId) ||
        !r.readFixed(header.wrapNonce) ||
        !r.readFixed(header.wrappedKey) ||
        !r.readFixed(header.payloadNonce))
        return VaultCoreStatus.corruptData;

    ulong payloadCipherLength;
    if (!r.readU64(payloadCipherLength))
        return VaultCoreStatus.corruptData;

    if (namespaceLength == 0 || namespaceLength > 96)
        return VaultCoreStatus.corruptData;

    if (payloadCipherLength < aeadTagBytes ||
        payloadCipherLength > maxPayloadBytes + aeadTagBytes ||
        payloadCipherLength > size_t.max)
        return VaultCoreStatus.corruptData;

    bool namespaceMatches;
    if (!r.readNamespace(
        namespaceLength,
        expectedNamespace.serialize(),
        namespaceMatches
    ))
        return VaultCoreStatus.corruptData;

    if (!namespaceMatches)
        return VaultCoreStatus.invalidInput;

    header.payloadCipherOffset = r.pos;
    header.payloadCipherLength = cast(size_t) payloadCipherLength;

    if (!r.skip(header.payloadCipherLength))
        return VaultCoreStatus.corruptData;

    if (r.pos != image.length)
        return VaultCoreStatus.corruptData;

    return VaultCoreStatus.ok;
}

ubyte[] buildWrapAd(
    CredentialNamespace ns,
    uint ops,
    ulong memBytes,
    scope const ubyte[pwhashSaltBytes] salt,
    scope const ubyte[16] vaultId
) @safe
{
    const nsText = ns.serialize();
    enum string domain = "credentials-d:wrap:v1";

    const total =
        domain.length + 2 + 2 + 4 + 8 +
        salt.length + vaultId.length + nsText.length;

    auto result = new ubyte[total];
    Writer w = Writer(result, 0);
    assert(w.putAscii(domain));
    assert(w.putU16(formatVersion));
    assert(w.putU16(cast(ushort)nsText.length));
    assert(w.putU32(ops));
    assert(w.putU64(memBytes));
    assert(w.put(salt[]));
    assert(w.put(vaultId[]));
    assert(w.putAscii(nsText));
    assert(w.pos == result.length);
    return result;
}

ubyte[] buildPayloadAd(
    CredentialNamespace ns,
    scope const ubyte[16] vaultId
) @safe
{
    const nsText = ns.serialize();
    enum string domain = "credentials-d:payload:v1";

    const total =
        domain.length + 2 + vaultId.length + nsText.length;

    auto result = new ubyte[total];
    Writer w = Writer(result, 0);
    assert(w.putAscii(domain));
    assert(w.putU16(formatVersion));
    assert(w.put(vaultId[]));
    assert(w.putAscii(nsText));
    assert(w.pos == result.length);
    return result;
}

bool deriveKekBytes(
    scope const(ubyte)[] bytes,
    scope const ubyte[pwhashSaltBytes] salt,
    uint ops,
    ulong memBytes,
    ref ubyte[vaultKeyBytes] kek
) @trusted
{
    const(char)* passwordPtr =
        bytes.length == 0 ? null : cast(const(char)*)bytes.ptr;

    return crypto_pwhash(
        kek.ptr,
        kek.length,
        passwordPtr,
        bytes.length,
        salt.ptr,
        ops,
        cast(size_t)memBytes,
        crypto_pwhash_alg_argon2id13()
    ) == 0;
}

bool deriveKek(
    scope ref const SecretBuffer passphrase,
    scope const ubyte[pwhashSaltBytes] salt,
    uint ops,
    ulong memBytes,
    ref ubyte[vaultKeyBytes] kek
) @trusted
{
    if (passphrase.empty || !validKdf(ops, memBytes))
        return false;

    bool success;
    passphrase.withBytes((scope const(ubyte)[] bytes) @safe
    {
        success = deriveKekBytes(
            bytes,
            salt,
            ops,
            memBytes,
            kek
        );
    });

    return success;
}

VaultCoreStatus unwrapKey(
    ref const HeaderView header,
    CredentialNamespace ns,
    scope ref const SecretBuffer passphrase,
    ref ubyte[vaultKeyBytes] vaultKey
) @trusted
{
    ubyte[vaultKeyBytes] kek;
    scope(exit) zeroFixed(kek);

    if (!deriveKek(
        passphrase,
        header.salt,
        header.ops,
        header.memBytes,
        kek
    ))
        return VaultCoreStatus.backendFailure;

    auto ad = buildWrapAd(
        ns,
        header.ops,
        header.memBytes,
        header.salt,
        header.vaultId
    );

    ulong plaintextLength;
    const rc = crypto_aead_xchacha20poly1305_ietf_decrypt(
        vaultKey.ptr,
        &plaintextLength,
        null,
        header.wrappedKey.ptr,
        header.wrappedKey.length,
        ad.ptr,
        ad.length,
        header.wrapNonce.ptr,
        kek.ptr
    );

    if (rc != 0 || plaintextLength != vaultKey.length)
    {
        zeroFixed(vaultKey);
        return VaultCoreStatus.permissionDenied;
    }

    return VaultCoreStatus.ok;
}

VaultCoreStatus decryptPayload(
    scope const(ubyte)[] image,
    ref const HeaderView header,
    CredentialNamespace ns,
    scope const(ubyte)[] vaultKey,
    out ubyte[] plaintext
) @trusted
{
    plaintext = null;

    if (vaultKey.length != vaultKeyBytes)
        return VaultCoreStatus.invalidInput;

    if (header.payloadCipherOffset > image.length ||
        header.payloadCipherLength > image.length - header.payloadCipherOffset ||
        header.payloadCipherLength < aeadTagBytes)
        return VaultCoreStatus.corruptData;

    const expectedLength =
        header.payloadCipherLength - aeadTagBytes;

    if (expectedLength > maxPayloadBytes)
        return VaultCoreStatus.corruptData;

    const cipher = image[
        header.payloadCipherOffset ..
        header.payloadCipherOffset + header.payloadCipherLength
    ];

    plaintext = new ubyte[expectedLength];

    auto ad = buildPayloadAd(ns, header.vaultId);

    ulong actualLength;
    const rc = crypto_aead_xchacha20poly1305_ietf_decrypt(
        plaintext.length == 0 ? null : plaintext.ptr,
        &actualLength,
        null,
        cipher.ptr,
        cipher.length,
        ad.ptr,
        ad.length,
        header.payloadNonce.ptr,
        vaultKey.ptr
    );

    if (rc != 0 || actualLength != expectedLength)
    {
        zero(plaintext);
        plaintext = null;
        return VaultCoreStatus.corruptData;
    }

    return VaultCoreStatus.ok;
}

VaultCoreStatus encryptPayload(
    CredentialNamespace ns,
    scope const ubyte[16] vaultId,
    scope const(ubyte)[] vaultKey,
    scope const(ubyte)[] plaintext,
    ref ubyte[xNonceBytes] nonce,
    out ubyte[] cipher
) @trusted
{
    cipher = null;

    if (vaultKey.length != vaultKeyBytes)
        return VaultCoreStatus.invalidInput;

    if (plaintext.length > maxPayloadBytes)
        return VaultCoreStatus.tooLarge;

    randombytes_buf(nonce.ptr, nonce.length);

    cipher = new ubyte[plaintext.length + aeadTagBytes];
    auto ad = buildPayloadAd(ns, vaultId);

    ulong cipherLength;
    const rc = crypto_aead_xchacha20poly1305_ietf_encrypt(
        cipher.ptr,
        &cipherLength,
        plaintext.length == 0 ? null : plaintext.ptr,
        plaintext.length,
        ad.ptr,
        ad.length,
        null,
        nonce.ptr,
        vaultKey.ptr
    );

    if (rc != 0 || cipherLength != cipher.length)
    {
        cipher = null;
        return VaultCoreStatus.backendFailure;
    }

    return VaultCoreStatus.ok;
}

VaultCoreStatus parsePayload(
    scope const(ubyte)[] plaintext,
    out RecordView[] records
) @safe
{
    records = null;

    Reader r = Reader(plaintext, 0);

    if (!r.expect(payloadMagic[]))
        return VaultCoreStatus.corruptData;

    uint count;
    if (!r.readU32(count) || count > maxRecords)
        return VaultCoreStatus.corruptData;

    records = new RecordView[count];

    foreach (i; 0 .. count)
    {
        if (!r.readFixed(records[i].id))
            return VaultCoreStatus.corruptData;

        uint secretLength;
        if (!r.readU32(secretLength) ||
            secretLength > maxSecretBytes)
            return VaultCoreStatus.corruptData;

        records[i].secretOffset = r.pos;
        records[i].secretLength = secretLength;

        if (!r.skip(secretLength))
            return VaultCoreStatus.corruptData;

        foreach (j; 0 .. i)
        {
            if (records[j].id == records[i].id)
                return VaultCoreStatus.corruptData;
        }
    }

    if (r.pos != plaintext.length)
        return VaultCoreStatus.corruptData;

    return VaultCoreStatus.ok;
}

bool payloadSizeFor(
    scope const RecordView[] records,
    ptrdiff_t replacementIndex,
    size_t replacementLength,
    bool appendRecord,
    out size_t total
) @nogc nothrow @safe
{
    total = payloadMagic.length + 4;

    size_t count = records.length + (appendRecord ? 1 : 0);
    if (count > maxRecords)
        return false;

    foreach (i, ref const record; records)
    {
        const length =
            cast(ptrdiff_t)i == replacementIndex
            ? replacementLength
            : record.secretLength;

        if (length > maxSecretBytes)
            return false;

        const add = 16 + 4 + length;
        if (total > maxPayloadBytes ||
            add > maxPayloadBytes - total)
            return false;
        total += add;
    }

    if (appendRecord)
    {
        if (replacementLength > maxSecretBytes)
            return false;
        const add = 16 + 4 + replacementLength;
        if (total > maxPayloadBytes ||
            add > maxPayloadBytes - total)
            return false;
        total += add;
    }

    return total <= maxPayloadBytes;
}

ubyte[] buildPayload(
    scope const(ubyte)[] sourcePayload,
    scope const RecordView[] records,
    ptrdiff_t replacementIndex,
    scope const(ubyte)[] replacement,
    bool appendRecord,
    scope const ubyte[16] appendId
) @safe
{
    size_t total;
    if (!payloadSizeFor(
        records,
        replacementIndex,
        replacement.length,
        appendRecord,
        total
    ))
        return null;

    auto result = new ubyte[total];
    Writer w = Writer(result, 0);

    assert(w.put(payloadMagic[]));
    const count =
        cast(uint)(records.length + (appendRecord ? 1 : 0));
    assert(w.putU32(count));

    foreach (i, ref const record; records)
    {
        const(ubyte)[] bytes;

        if (cast(ptrdiff_t)i == replacementIndex)
        {
            bytes = replacement;
        }
        else
        {
            if (record.secretOffset > sourcePayload.length ||
                record.secretLength >
                    sourcePayload.length - record.secretOffset)
                return null;

            bytes = sourcePayload[
                record.secretOffset ..
                record.secretOffset + record.secretLength
            ];
        }

        assert(w.put(record.id[]));
        assert(w.putU32(cast(uint)bytes.length));
        assert(w.put(bytes));
    }

    if (appendRecord)
    {
        assert(w.put(appendId[]));
        assert(w.putU32(cast(uint)replacement.length));
        assert(w.put(replacement));
    }

    assert(w.pos == result.length);
    return result;
}

ubyte[] emptyPayload() @safe
{
    auto result = new ubyte[payloadMagic.length + 4];
    Writer w = Writer(result, 0);
    assert(w.put(payloadMagic[]));
    assert(w.putU32(0));
    return result;
}

ubyte[] serializeImage(
    CredentialNamespace ns,
    ref const HeaderView header,
    scope const(ubyte)[] payloadCipher
) @safe
{
    const nsText = ns.serialize();

    if (payloadCipher.length > maxPayloadBytes + aeadTagBytes)
        return null;

    const total =
        fixedHeaderBytes + nsText.length + payloadCipher.length;

    auto result = new ubyte[total];
    Writer w = Writer(result, 0);

    assert(w.put(vaultMagic[]));
    assert(w.putU16(formatVersion));
    assert(w.putU16(cast(ushort)nsText.length));
    assert(w.putU16(kdfArgon2id));
    assert(w.putU16(0));
    assert(w.putU32(header.ops));
    assert(w.putU64(header.memBytes));
    assert(w.put(header.salt[]));
    assert(w.put(header.vaultId[]));
    assert(w.put(header.wrapNonce[]));
    assert(w.put(header.wrappedKey[]));
    assert(w.put(header.payloadNonce[]));
    assert(w.putU64(payloadCipher.length));
    assert(w.putAscii(nsText));
    assert(w.put(payloadCipher));
    assert(w.pos == result.length);

    return result;
}

bool parseLocator(string locator, ref ubyte[16] id)
    @nogc nothrow @safe
{
    if (locator.length != 32)
        return false;

    foreach (i; 0 .. 16)
    {
        const hi = hexNibble(locator[i * 2]);
        const lo = hexNibble(locator[i * 2 + 1]);
        if (hi < 0 || lo < 0)
            return false;
        id[i] = cast(ubyte)((hi << 4) | lo);
    }

    return true;
}

int hexNibble(char c) @nogc nothrow @safe
{
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    return -1;
}

string locatorOf(scope const ubyte[16] id) @safe
{
    enum string digits = "0123456789abcdef";
    char[32] chars;

    foreach (i; 0 .. 16)
    {
        chars[i * 2] = digits[id[i] >> 4];
        chars[i * 2 + 1] = digits[id[i] & 0x0f];
    }

    return chars[].idup;
}

ptrdiff_t findRecord(
    scope const RecordView[] records,
    scope const ubyte[16] id
) @nogc nothrow @safe
{
    foreach (i, ref const record; records)
        if (record.id == id)
            return cast(ptrdiff_t)i;
    return -1;
}

bool generateUniqueId(
    scope const RecordView[] records,
    ref ubyte[16] id
) @trusted
{
    foreach (_; 0 .. 4)
    {
        randombytes_buf(id.ptr, id.length);
        if (findRecord(records, id) < 0)
            return true;
    }
    return false;
}

VaultCoreStatus openPayload(
    scope const(ubyte)[] image,
    CredentialNamespace ns,
    scope ref const SecretBuffer passphrase,
    out HeaderView header,
    out ubyte[] plaintext,
    out RecordView[] records,
    ref ubyte[vaultKeyBytes] vaultKey
) @safe
{
    plaintext = null;
    records = null;

    auto status = parseHeader(image, ns, header);
    if (status != VaultCoreStatus.ok)
        return status;

    status = unwrapKey(header, ns, passphrase, vaultKey);
    if (status != VaultCoreStatus.ok)
        return status;

    status = decryptPayload(image, header, ns, vaultKey, plaintext);
    if (status != VaultCoreStatus.ok)
        return status;

    status = parsePayload(plaintext, records);
    if (status != VaultCoreStatus.ok)
    {
        zero(plaintext);
        plaintext = null;
        records = null;
        return status;
    }

    return VaultCoreStatus.ok;
}


package(credentials.backend.vault):

enum size_t maximumVaultImageBytes =
    fixedHeaderBytes + 96 + maxPayloadBytes + aeadTagBytes;

VaultCoreStatus unlockVaultSession(
    scope const(ubyte)[] image,
    CredentialNamespace ns,
    scope ref const SecretBuffer passphrase,
    VaultSession session
) @safe
{
    if (session is null)
        return VaultCoreStatus.invalidInput;

    if (!sodiumReady())
        return VaultCoreStatus.unavailable;

    HeaderView header;
    auto status = parseHeader(image, ns, header);
    if (status != VaultCoreStatus.ok)
        return status;

    ubyte[vaultKeyBytes] vaultKey;
    scope(exit) zeroFixed(vaultKey);

    status = unwrapKey(header, ns, passphrase, vaultKey);
    if (status != VaultCoreStatus.ok)
        return status;

    ubyte[] plaintext;
    scope(exit)
    {
        if (plaintext !is null)
            zero(plaintext);
    }

    status = decryptPayload(
        image,
        header,
        ns,
        vaultKey[],
        plaintext
    );
    if (status != VaultCoreStatus.ok)
        return status;

    RecordView[] records;
    status = parsePayload(plaintext, records);
    if (status != VaultCoreStatus.ok)
        return status;

    session.set(vaultKey[], header.vaultId);
    return VaultCoreStatus.ok;
}

VaultCoreStatus openPayloadUnlocked(
    scope const(ubyte)[] image,
    CredentialNamespace ns,
    VaultSession session,
    out HeaderView header,
    out ubyte[] plaintext,
    out RecordView[] records
) @safe
{
    plaintext = null;
    records = null;

    if (session is null || !session.unlocked)
        return VaultCoreStatus.locked;

    auto status = parseHeader(image, ns, header);
    if (status != VaultCoreStatus.ok)
        return status;

    if (!session.matchesVault(header.vaultId))
        return VaultCoreStatus.locked;

    status = VaultCoreStatus.backendFailure;
    session.withKey((scope const(ubyte)[] key) @safe
    {
        status = decryptPayload(
            image,
            header,
            ns,
            key,
            plaintext
        );
    });

    if (status != VaultCoreStatus.ok)
        return status;

    status = parsePayload(plaintext, records);
    if (status != VaultCoreStatus.ok)
    {
        zero(plaintext);
        plaintext = null;
        records = null;
        return status;
    }

    return VaultCoreStatus.ok;
}

VaultCoreStatus encryptPayloadUnlocked(
    VaultSession session,
    CredentialNamespace ns,
    scope const ubyte[16] vaultId,
    scope const(ubyte)[] plaintext,
    ref ubyte[xNonceBytes] nonce,
    out ubyte[] cipher
) @safe
{
    cipher = null;

    if (session is null || !session.unlocked)
        return VaultCoreStatus.locked;

    if (!session.matchesVault(vaultId))
        return VaultCoreStatus.locked;

    auto status = VaultCoreStatus.backendFailure;
    session.withKey((scope const(ubyte)[] key) @safe
    {
        status = encryptPayload(
            ns,
            vaultId,
            key,
            plaintext,
            nonce,
            cipher
        );
    });

    return status;
}

VaultCoreStatus vaultPutUnlocked(
    ref ubyte[] image,
    CredentialNamespace ns,
    VaultSession session,
    scope ref const SecretBuffer secret,
    out string locator
) @safe
{
    locator = null;

    if (secret.length > maxSecretBytes)
        return VaultCoreStatus.tooLarge;

    HeaderView header;
    ubyte[] plaintext;
    RecordView[] records;
    scope(exit)
    {
        if (plaintext !is null)
            zero(plaintext);
    }

    auto status = openPayloadUnlocked(
        image,
        ns,
        session,
        header,
        plaintext,
        records
    );
    if (status != VaultCoreStatus.ok)
        return status;

    ubyte[16] id;
    if (!generateUniqueId(records, id))
        return VaultCoreStatus.backendFailure;

    ubyte[] nextPayload;
    secret.withBytes((scope const(ubyte)[] bytes) @safe
    {
        nextPayload = buildPayload(
            plaintext,
            records,
            -1,
            bytes,
            true,
            id
        );
    });
    if (nextPayload is null)
        return VaultCoreStatus.tooLarge;
    scope(exit) zero(nextPayload);

    ubyte[] nextCipher;
    status = encryptPayloadUnlocked(
        session,
        ns,
        header.vaultId,
        nextPayload,
        header.payloadNonce,
        nextCipher
    );
    if (status != VaultCoreStatus.ok)
        return status;

    auto nextImage = serializeImage(ns, header, nextCipher);
    if (nextImage is null)
        return VaultCoreStatus.backendFailure;

    image = nextImage;
    locator = locatorOf(id);
    return VaultCoreStatus.ok;
}

VaultCoreStatus vaultAcquireUnlocked(
    scope const(ubyte)[] image,
    CredentialNamespace ns,
    VaultSession session,
    string locator,
    scope SecretVisitor visitor
) @safe
{
    if (visitor is null)
        return VaultCoreStatus.invalidInput;

    ubyte[16] id;
    if (!parseLocator(locator, id))
        return VaultCoreStatus.invalidInput;

    HeaderView header;
    ubyte[] plaintext;
    RecordView[] records;
    scope(exit)
    {
        if (plaintext !is null)
            zero(plaintext);
    }

    auto status = openPayloadUnlocked(
        image,
        ns,
        session,
        header,
        plaintext,
        records
    );
    if (status != VaultCoreStatus.ok)
        return status;

    const index = findRecord(records, id);
    if (index < 0)
        return VaultCoreStatus.notFound;

    const record = records[cast(size_t)index];
    if (record.secretOffset > plaintext.length ||
        record.secretLength > plaintext.length - record.secretOffset)
        return VaultCoreStatus.corruptData;

    visitor(plaintext[
        record.secretOffset ..
        record.secretOffset + record.secretLength
    ]);
    return VaultCoreStatus.ok;
}

VaultCoreStatus vaultReplaceUnlocked(
    ref ubyte[] image,
    CredentialNamespace ns,
    VaultSession session,
    string locator,
    scope ref const SecretBuffer replacement
) @safe
{
    if (replacement.length > maxSecretBytes)
        return VaultCoreStatus.tooLarge;

    ubyte[16] id;
    if (!parseLocator(locator, id))
        return VaultCoreStatus.invalidInput;

    HeaderView header;
    ubyte[] plaintext;
    RecordView[] records;
    scope(exit)
    {
        if (plaintext !is null)
            zero(plaintext);
    }

    auto status = openPayloadUnlocked(
        image,
        ns,
        session,
        header,
        plaintext,
        records
    );
    if (status != VaultCoreStatus.ok)
        return status;

    const index = findRecord(records, id);
    if (index < 0)
        return VaultCoreStatus.notFound;

    ubyte[] nextPayload;
    replacement.withBytes((scope const(ubyte)[] bytes) @safe
    {
        nextPayload = buildPayload(
            plaintext,
            records,
            index,
            bytes,
            false,
            id
        );
    });
    if (nextPayload is null)
        return VaultCoreStatus.tooLarge;
    scope(exit) zero(nextPayload);

    ubyte[] nextCipher;
    status = encryptPayloadUnlocked(
        session,
        ns,
        header.vaultId,
        nextPayload,
        header.payloadNonce,
        nextCipher
    );
    if (status != VaultCoreStatus.ok)
        return status;

    auto nextImage = serializeImage(ns, header, nextCipher);
    if (nextImage is null)
        return VaultCoreStatus.backendFailure;

    image = nextImage;
    return VaultCoreStatus.ok;
}

VaultCoreStatus vaultRemoveUnlocked(
    ref ubyte[] image,
    CredentialNamespace ns,
    VaultSession session,
    string locator
) @safe
{
    ubyte[16] id;
    if (!parseLocator(locator, id))
        return VaultCoreStatus.invalidInput;

    HeaderView header;
    ubyte[] plaintext;
    RecordView[] records;
    scope(exit)
    {
        if (plaintext !is null)
            zero(plaintext);
    }

    auto status = openPayloadUnlocked(
        image,
        ns,
        session,
        header,
        plaintext,
        records
    );
    if (status != VaultCoreStatus.ok)
        return status;

    const index = findRecord(records, id);
    if (index < 0)
        return VaultCoreStatus.notFound;

    size_t total = payloadMagic.length + 4;
    foreach (i, ref const record; records)
    {
        if (i == cast(size_t)index)
            continue;

        const add = 16 + 4 + record.secretLength;
        if (add > maxPayloadBytes - total)
            return VaultCoreStatus.corruptData;
        total += add;
    }

    auto nextPayload = new ubyte[total];
    scope(exit) zero(nextPayload);
    Writer w = Writer(nextPayload, 0);
    assert(w.put(payloadMagic[]));
    assert(w.putU32(cast(uint)(records.length - 1)));

    foreach (i, ref const record; records)
    {
        if (i == cast(size_t)index)
            continue;

        if (record.secretOffset > plaintext.length ||
            record.secretLength > plaintext.length - record.secretOffset)
            return VaultCoreStatus.corruptData;

        assert(w.put(record.id[]));
        assert(w.putU32(cast(uint)record.secretLength));
        assert(w.put(plaintext[
            record.secretOffset ..
            record.secretOffset + record.secretLength
        ]));
    }

    ubyte[] nextCipher;
    status = encryptPayloadUnlocked(
        session,
        ns,
        header.vaultId,
        nextPayload,
        header.payloadNonce,
        nextCipher
    );
    if (status != VaultCoreStatus.ok)
        return status;

    auto nextImage = serializeImage(ns, header, nextCipher);
    if (nextImage is null)
        return VaultCoreStatus.backendFailure;

    image = nextImage;
    return VaultCoreStatus.ok;
}

private:

public:

/**
 * Create a version-1 empty encrypted vault image.
 */
VaultCoreStatus createEmptyVaultImage(
    CredentialNamespace ns,
    scope ref const SecretBuffer passphrase,
    out ubyte[] image
) @trusted
{
    image = null;

    if (!ns.valid || passphrase.empty)
        return VaultCoreStatus.invalidInput;

    if (!sodiumReady())
        return VaultCoreStatus.unavailable;

    HeaderView header;
    header.ops = defaultOps;
    header.memBytes = defaultMemBytes;

    ubyte[vaultKeyBytes] vaultKey;
    ubyte[vaultKeyBytes] kek;
    scope(exit)
    {
        zeroFixed(vaultKey);
        zeroFixed(kek);
    }

    randombytes_buf(header.salt.ptr, header.salt.length);
    randombytes_buf(header.vaultId.ptr, header.vaultId.length);
    randombytes_buf(header.wrapNonce.ptr, header.wrapNonce.length);
    randombytes_buf(vaultKey.ptr, vaultKey.length);

    if (!deriveKek(
        passphrase,
        header.salt,
        header.ops,
        header.memBytes,
        kek
    ))
        return VaultCoreStatus.backendFailure;

    auto wrapAd = buildWrapAd(
        ns,
        header.ops,
        header.memBytes,
        header.salt,
        header.vaultId
    );

    ulong wrappedLength;
    if (crypto_aead_xchacha20poly1305_ietf_encrypt(
        header.wrappedKey.ptr,
        &wrappedLength,
        vaultKey.ptr,
        vaultKey.length,
        wrapAd.ptr,
        wrapAd.length,
        null,
        header.wrapNonce.ptr,
        kek.ptr
    ) != 0 ||
        wrappedLength != header.wrappedKey.length)
        return VaultCoreStatus.backendFailure;

    auto payload = emptyPayload();
    scope(exit) zero(payload);

    ubyte[] payloadCipher;
    auto status = encryptPayload(
        ns,
        header.vaultId,
        vaultKey,
        payload,
        header.payloadNonce,
        payloadCipher
    );
    if (status != VaultCoreStatus.ok)
        return status;

    image = serializeImage(ns, header, payloadCipher);
    if (image is null)
        return VaultCoreStatus.backendFailure;

    return VaultCoreStatus.ok;
}

/**
 * Add a credential to an encrypted in-memory vault image.
 */
VaultCoreStatus vaultPut(
    ref ubyte[] image,
    CredentialNamespace ns,
    scope ref const SecretBuffer passphrase,
    scope ref const SecretBuffer secret,
    out string locator
) @safe
{
    locator = null;

    if (secret.length > maxSecretBytes)
        return VaultCoreStatus.tooLarge;

    if (!sodiumReady())
        return VaultCoreStatus.unavailable;

    HeaderView header;
    ubyte[] plaintext;
    RecordView[] records;
    ubyte[vaultKeyBytes] vaultKey;
    scope(exit)
    {
        if (plaintext !is null)
            zero(plaintext);
        zeroFixed(vaultKey);
    }

    auto status = openPayload(
        image,
        ns,
        passphrase,
        header,
        plaintext,
        records,
        vaultKey
    );
    if (status != VaultCoreStatus.ok)
        return status;

    ubyte[16] id;
    if (!generateUniqueId(records, id))
        return VaultCoreStatus.backendFailure;

    ubyte[] nextPayload;
    secret.withBytes((scope const(ubyte)[] bytes) @safe
    {
        nextPayload = buildPayload(
            plaintext,
            records,
            -1,
            bytes,
            true,
            id
        );
    });
    if (nextPayload is null)
        return VaultCoreStatus.tooLarge;
    scope(exit) zero(nextPayload);

    ubyte[] nextCipher;
    status = encryptPayload(
        ns,
        header.vaultId,
        vaultKey,
        nextPayload,
        header.payloadNonce,
        nextCipher
    );
    if (status != VaultCoreStatus.ok)
        return status;

    auto nextImage = serializeImage(ns, header, nextCipher);
    if (nextImage is null)
        return VaultCoreStatus.backendFailure;

    image = nextImage;
    locator = locatorOf(id);
    return VaultCoreStatus.ok;
}

/**
 * Acquire one credential from an encrypted image.
 */
VaultCoreStatus vaultAcquire(
    scope const(ubyte)[] image,
    CredentialNamespace ns,
    scope ref const SecretBuffer passphrase,
    string locator,
    scope SecretVisitor visitor
) @safe
{
    if (visitor is null)
        return VaultCoreStatus.invalidInput;

    ubyte[16] id;
    if (!parseLocator(locator, id))
        return VaultCoreStatus.invalidInput;

    if (!sodiumReady())
        return VaultCoreStatus.unavailable;

    HeaderView header;
    ubyte[] plaintext;
    RecordView[] records;
    ubyte[vaultKeyBytes] vaultKey;
    scope(exit)
    {
        if (plaintext !is null)
            zero(plaintext);
        zeroFixed(vaultKey);
    }

    auto status = openPayload(
        image,
        ns,
        passphrase,
        header,
        plaintext,
        records,
        vaultKey
    );
    if (status != VaultCoreStatus.ok)
        return status;

    const index = findRecord(records, id);
    if (index < 0)
        return VaultCoreStatus.notFound;

    const record = records[cast(size_t)index];

    if (record.secretOffset > plaintext.length ||
        record.secretLength > plaintext.length - record.secretOffset)
        return VaultCoreStatus.corruptData;

    visitor(plaintext[
        record.secretOffset ..
        record.secretOffset + record.secretLength
    ]);
    return VaultCoreStatus.ok;
}

/**
 * Replace one credential without changing its locator.
 */
VaultCoreStatus vaultReplace(
    ref ubyte[] image,
    CredentialNamespace ns,
    scope ref const SecretBuffer passphrase,
    string locator,
    scope ref const SecretBuffer replacement
) @safe
{
    if (replacement.length > maxSecretBytes)
        return VaultCoreStatus.tooLarge;

    ubyte[16] id;
    if (!parseLocator(locator, id))
        return VaultCoreStatus.invalidInput;

    if (!sodiumReady())
        return VaultCoreStatus.unavailable;

    HeaderView header;
    ubyte[] plaintext;
    RecordView[] records;
    ubyte[vaultKeyBytes] vaultKey;
    scope(exit)
    {
        if (plaintext !is null)
            zero(plaintext);
        zeroFixed(vaultKey);
    }

    auto status = openPayload(
        image,
        ns,
        passphrase,
        header,
        plaintext,
        records,
        vaultKey
    );
    if (status != VaultCoreStatus.ok)
        return status;

    const index = findRecord(records, id);
    if (index < 0)
        return VaultCoreStatus.notFound;

    ubyte[] nextPayload;
    replacement.withBytes((scope const(ubyte)[] bytes) @safe
    {
        nextPayload = buildPayload(
            plaintext,
            records,
            index,
            bytes,
            false,
            id
        );
    });
    if (nextPayload is null)
        return VaultCoreStatus.tooLarge;
    scope(exit) zero(nextPayload);

    ubyte[] nextCipher;
    status = encryptPayload(
        ns,
        header.vaultId,
        vaultKey,
        nextPayload,
        header.payloadNonce,
        nextCipher
    );
    if (status != VaultCoreStatus.ok)
        return status;

    auto nextImage = serializeImage(ns, header, nextCipher);
    if (nextImage is null)
        return VaultCoreStatus.backendFailure;

    image = nextImage;
    return VaultCoreStatus.ok;
}

/**
 * Remove one credential from an encrypted image.
 */
VaultCoreStatus vaultRemove(
    ref ubyte[] image,
    CredentialNamespace ns,
    scope ref const SecretBuffer passphrase,
    string locator
) @safe
{
    ubyte[16] id;
    if (!parseLocator(locator, id))
        return VaultCoreStatus.invalidInput;

    if (!sodiumReady())
        return VaultCoreStatus.unavailable;

    HeaderView header;
    ubyte[] plaintext;
    RecordView[] records;
    ubyte[vaultKeyBytes] vaultKey;
    scope(exit)
    {
        if (plaintext !is null)
            zero(plaintext);
        zeroFixed(vaultKey);
    }

    auto status = openPayload(
        image,
        ns,
        passphrase,
        header,
        plaintext,
        records,
        vaultKey
    );
    if (status != VaultCoreStatus.ok)
        return status;

    const index = findRecord(records, id);
    if (index < 0)
        return VaultCoreStatus.notFound;

    size_t total = payloadMagic.length + 4;
    foreach (i, ref const record; records)
    {
        if (i == cast(size_t)index)
            continue;
        const add = 16 + 4 + record.secretLength;
        if (add > maxPayloadBytes - total)
            return VaultCoreStatus.corruptData;
        total += add;
    }

    auto nextPayload = new ubyte[total];
    scope(exit) zero(nextPayload);
    Writer w = Writer(nextPayload, 0);
    assert(w.put(payloadMagic[]));
    assert(w.putU32(cast(uint)(records.length - 1)));

    foreach (i, ref const record; records)
    {
        if (i == cast(size_t)index)
            continue;
        if (record.secretOffset > plaintext.length ||
            record.secretLength > plaintext.length - record.secretOffset)
            return VaultCoreStatus.corruptData;

        assert(w.put(record.id[]));
        assert(w.putU32(cast(uint)record.secretLength));
        assert(w.put(plaintext[
            record.secretOffset ..
            record.secretOffset + record.secretLength
        ]));
    }

    ubyte[] nextCipher;
    status = encryptPayload(
        ns,
        header.vaultId,
        vaultKey,
        nextPayload,
        header.payloadNonce,
        nextCipher
    );
    if (status != VaultCoreStatus.ok)
        return status;

    auto nextImage = serializeImage(ns, header, nextCipher);
    if (nextImage is null)
        return VaultCoreStatus.backendFailure;

    image = nextImage;
    return VaultCoreStatus.ok;
}

@("vault crypto core round trip")
unittest
{
    CredentialNamespace ns;
    assert(CredentialNamespace.tryParse("org.example.vaulttest", ns));

    auto passphrase =
        SecretBuffer(cast(const(ubyte)[]) "correct horse battery staple");
    auto wrong = SecretBuffer(cast(const(ubyte)[]) "wrong passphrase");

    ubyte[] image;
    assert(createEmptyVaultImage(ns, passphrase, image) ==
        VaultCoreStatus.ok);
    assert(image.length > fixedHeaderBytes);

    ubyte[] secretBytes = [
        0x41, 0x00, 0x42, 0xff, 0x43
    ];
    auto secret = SecretBuffer(secretBytes);

    string locator;
    assert(vaultPut(image, ns, passphrase, secret, locator) ==
        VaultCoreStatus.ok);
    assert(locator.length == 32);

    bool called;
    assert(vaultAcquire(
        image,
        ns,
        passphrase,
        locator,
        (scope const(ubyte)[] bytes) @safe
        {
            assert(bytes == secretBytes);
            called = true;
        }
    ) == VaultCoreStatus.ok);
    assert(called);

    bool wrongCalled;
    assert(vaultAcquire(
        image,
        ns,
        wrong,
        locator,
        (scope const(ubyte)[]) @safe
        {
            wrongCalled = true;
        }
    ) == VaultCoreStatus.permissionDenied);
    assert(!wrongCalled);

    auto replacement =
        SecretBuffer(cast(const(ubyte)[]) "replacement");
    assert(vaultReplace(
        image,
        ns,
        passphrase,
        locator,
        replacement
    ) == VaultCoreStatus.ok);

    assert(vaultAcquire(
        image,
        ns,
        passphrase,
        locator,
        (scope const(ubyte)[] bytes) @safe
        {
            assert(bytes == cast(const(ubyte)[]) "replacement");
        }
    ) == VaultCoreStatus.ok);

    assert(vaultRemove(image, ns, passphrase, locator) ==
        VaultCoreStatus.ok);

    assert(vaultAcquire(
        image,
        ns,
        passphrase,
        locator,
        (scope const(ubyte)[]) @safe {}
    ) == VaultCoreStatus.notFound);
}

@("vault corruption never exposes plaintext")
unittest
{
    CredentialNamespace ns;
    assert(CredentialNamespace.tryParse("org.example.vaulttamper", ns));

    auto passphrase = SecretBuffer(cast(const(ubyte)[]) "passphrase");

    ubyte[] image;
    assert(createEmptyVaultImage(ns, passphrase, image) ==
        VaultCoreStatus.ok);

    auto secret = SecretBuffer(cast(const(ubyte)[]) "SENTINEL_SECRET");
    string locator;
    assert(vaultPut(image, ns, passphrase, secret, locator) ==
        VaultCoreStatus.ok);

    // Flip one ciphertext bit in the final byte. The authentication tag must
    // fail before the visitor is invoked.
    auto tampered = image.dup;
    tampered[$ - 1] ^= 0x01;

    bool called;
    assert(vaultAcquire(
        tampered,
        ns,
        passphrase,
        locator,
        (scope const(ubyte)[]) @safe
        {
            called = true;
        }
    ) == VaultCoreStatus.corruptData);
    assert(!called);
}
