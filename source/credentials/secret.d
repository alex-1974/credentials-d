/**
 * Explicit secret-buffer ownership and scoped plaintext access.
 */
module credentials.secret;

import std.algorithm.mutation : fill;
import std.array : array;

/**
 * Owns one mutable copy of credential bytes.
 *
 * The object identity may be shared, but the contained plaintext is not copied
 * by copying a `SecretBuffer` reference. Call `clear` when the secret is no
 * longer needed; the destructor also performs the same best-effort clearing.
 *
 * This first implementation uses GC-managed mutable storage. Clearing is an
 * observable overwrite of the owned buffer, but no stronger guarantee is made
 * about compiler, runtime, allocator, swap, crash dumps, or copies created by
 * external code.
 *
 * Plaintext access is explicit through `withBytes`. The callback receives a
 * scoped, const view and must not retain it.
 */
final class SecretBuffer
{
    private ubyte[] bytes_;

    /**
     * Copy plaintext bytes into a new owned secret buffer.
     */
    this(scope const(ubyte)[] source) @safe
    {
        bytes_ = source.array;
    }

    /**
     * Best-effort clear on destruction.
     *
     * Consumers that need prompt clearing should call `clear` explicitly;
     * GC destruction timing is not a security guarantee.
     */
    ~this() @safe
    {
        clear();
    }

    /**
     * Number of currently owned plaintext bytes.
     */
    @property size_t length() const @nogc nothrow pure @safe
    {
        return bytes_.length;
    }

    /**
     * Whether this buffer currently contains no plaintext bytes.
     */
    @property bool empty() const @nogc nothrow pure @safe
    {
        return bytes_.length == 0;
    }

    /**
     * Invoke `visitor` with a scoped, read-only view of the plaintext.
     *
     * The returned view must not outlive the callback. Under DIP1000 the
     * `scope` parameter lets the compiler reject straightforward escapes.
     */
    void withBytes(scope void delegate(scope const(ubyte)[]) @safe visitor) @safe
    in (visitor !is null)
    {
        visitor(bytes_);
    }

    /**
     * Overwrite the currently owned mutable buffer and release the reference.
     *
     * This is a best-effort process-memory hygiene operation, not a claim of
     * physical secure erasure.
     */
    void clear() @safe
    {
        bytes_.fill(0);
        bytes_ = null;
    }

    /**
     * Redacted representation for accidental formatting/logging.
     */
    override string toString() const @safe
    {
        return "<SecretBuffer:redacted>";
    }

    /**
     * Create an independent byte copy for a credential-store backend.
     *
     * This operation is intentionally package-private: consumers receive
     * plaintext only through `withBytes`.
     */
    package(credentials) ubyte[] duplicateBytes() const @safe
    {
        return bytes_.array;
    }
}

@("SecretBuffer exposes plaintext only explicitly")
unittest
{
    ubyte[] input = [0x61, 0x62, 0x63];
    auto secret = new SecretBuffer(input);

    bool visited;
    secret.withBytes((scope const(ubyte)[] bytes) @safe
    {
        assert(bytes == input);
        visited = true;
    });

    assert(visited);
    assert(secret.length == 3);

    secret.clear();
    assert(secret.empty);
}

@("SecretBuffer formatting is redacted")
unittest
{
    import std.format : format;

    auto secret = new SecretBuffer(cast(const(ubyte)[]) "SENTINEL_SECRET");
    const rendered = format("%s", secret);

    assert(rendered == "<SecretBuffer:redacted>");
    assert(rendered != "SENTINEL_SECRET");
}
