/**
 * Explicit secret-buffer ownership and scoped plaintext access.
 */
module credentials.secret;

import core.exception : onOutOfMemoryError;
import core.stdc.stdlib : free, malloc;
import core.volatile : volatileStore;

/**
 * Owns one non-GC allocation containing credential plaintext.
 *
 * `SecretBuffer` is deliberately non-copyable. Moving the value transfers
 * ownership without duplicating the backing allocation.
 *
 * The destructor clears and frees the owned non-GC memory deterministically
 * when normal D value lifetime rules run. Consumers may call `clear`
 * explicitly when prompt destruction is desirable.
 *
 * Plaintext access is explicit through `withBytes`. The callback receives a
 * scoped, const view and must not retain it.
 *
 * This type cannot erase copies that existed before construction or that a
 * consumer deliberately creates inside the explicit callback. It also makes
 * no claim against a compromised process, register spills, swap, hibernation
 * or operating-system memory capture.
 */
struct SecretBuffer
{
    private ubyte* data_;
    private size_t length_;

    /**
     * Copy plaintext bytes once into owned non-GC memory.
     *
     * The source remains the caller's responsibility; credentials-d cannot
     * erase it after this constructor returns.
     */
    this(scope const(ubyte)[] source) @trusted
    {
        if (source.length == 0)
            return;

        data_ = cast(ubyte*) malloc(source.length);
        if (data_ is null)
            onOutOfMemoryError();

        length_ = source.length;
        data_[0 .. length_] = source[];
    }

    /**
     * Secrets are not copyable. Use D move semantics when ownership transfer is
     * required.
     */
    @disable this(this);

    /**
     * Clear and release the owned non-GC allocation.
     */
    ~this() nothrow @nogc @trusted
    {
        clear();
    }

    /**
     * Number of currently owned plaintext bytes.
     */
    @property size_t length() const @nogc nothrow pure @safe
    {
        return length_;
    }

    /**
     * Whether this buffer currently owns no plaintext bytes.
     */
    @property bool empty() const @nogc nothrow pure @safe
    {
        return length_ == 0;
    }

    /**
     * Invoke `visitor` with a scoped, read-only view of the plaintext.
     *
     * Under DIP1000, straightforward attempts to retain the view outside the
     * callback are rejected by the compiler.
     */
    void withBytes(
        scope void delegate(scope const(ubyte)[]) @safe visitor
    ) const scope @trusted
    in (visitor !is null)
    {
        const(ubyte)[] view;

        if (data_ !is null)
            view = data_[0 .. length_];

        visitor(view);
    }

    /**
     * Securely overwrite the owned allocation and release it.
     *
     * The overwrite uses `core.volatile.volatileStore`, whose writes are
     * compiler-recognized and guaranteed not to be removed as dead stores.
     *
     * This is a process-memory hygiene guarantee for this allocation only, not
     * a claim that all historical copies of the credential have been erased.
     */
    void clear() scope nothrow @nogc @trusted
    {
        if (data_ is null)
        {
            length_ = 0;
            return;
        }

        secureZero(data_, length_);
        free(data_);

        data_ = null;
        length_ = 0;
    }

    /*
     * Intentionally no toString/opFormat implementation.
     *
     * SecretBuffer is non-copyable, so common variadic formatting paths reject
     * it at compile time instead of producing any textual representation.
     */
}

/**
 * Overwrite a memory region using compiler-recognized volatile stores.
 */
private void secureZero(ubyte* data, size_t length)
    nothrow @nogc @trusted
{
    foreach (i; 0 .. length)
        volatileStore(data + i, cast(ubyte) 0);
}

@("SecretBuffer exposes plaintext only explicitly")
unittest
{
    ubyte[] input = [0x61, 0x62, 0x63];
    auto secret = SecretBuffer(input);

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

@("secureZero overwrites every byte")
unittest
{
    enum size_t count = 32;
    auto memory = cast(ubyte*) malloc(count);
    assert(memory !is null);

    memory[0 .. count] = 0xA5;
    secureZero(memory, count);

    foreach (value; memory[0 .. count])
        assert(value == 0);

    free(memory);
}
