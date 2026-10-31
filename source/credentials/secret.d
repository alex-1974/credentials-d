/**
 * Secret values that should stay out of ordinary application state.
 */
module credentials.secret;

import core.exception : onOutOfMemoryError;
import core.stdc.stdlib : free, malloc;
import core.volatile : volatileStore;

/**
 * Buffer for a password, token or other credential value.
 *
 * Create a SecretBuffer before passing a secret to a credential store. Use
 * withBytes() only when an API actually needs the bytes, and keep that work
 * inside the callback.
 *
 * SecretBuffer cannot be copied accidentally. Call clear() when the
 * application no longer needs the value and wants to release it immediately.
 *
 * Examples:
 * ---
 * auto token = SecretBuffer(tokenBytes);
 *
 * CredentialHandle handle;
 * store.save(token, handle);
 *
 * token.clear();
 * ---
 */
struct SecretBuffer
{
    private ubyte* data_;
    private size_t length_;

    /**
     * Create a secret buffer from bytes you already have.
     *
     * Params:
     *     source = Secret bytes to place in the buffer.
     *
     * Note:
     *     The source array is still owned by the caller. Clear or discard it
     *     according to the needs of your application.
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
     * SecretBuffer values cannot be copied.
     */
    @disable this(this);

    /**
     * Clear and release this secret immediately.
     */
    ~this() nothrow @nogc @trusted
    {
        clear();
    }

    /**
     * Number of bytes in this secret.
     */
    @property size_t length() const scope @nogc nothrow pure @safe
    {
        return length_;
    }

    /**
     * Whether this secret currently contains no bytes.
     */
    @property bool empty() const scope @nogc nothrow pure @safe
    {
        return length_ == 0;
    }

    /**
     * Use the secret bytes for one operation.
     *
     * Keep the operation that needs the secret inside callback.
     *
     * Params:
     *     callback = Code that uses the secret bytes.
     *
     * Examples:
     * ---
     * secret.withBytes((scope const(ubyte)[] bytes) @safe
     * {
     *     // Call the API that needs bytes here.
     * });
     * ---
     */
    void withBytes(
        scope void delegate(scope const(ubyte)[]) @safe callback
    ) const scope @trusted
    in (callback !is null)
    {
        const(ubyte)[] view;

        if (data_ !is null)
            view = data_[0 .. length_];

        callback(view);
    }

    /**
     * Clear the secret and make this buffer empty.
     *
     * Call this when the application is finished with a long-lived secret
     * before the normal value lifetime ends.
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

    /**
     * Replace the owned plaintext with one new copy.
     *
     * This package-private operation allocates the replacement before clearing
     * the current value, so allocation failure leaves the current secret
     * intact. It is used by credential backends that retain a derived secret
     * such as an unlocked vault key.
     */
    package(credentials) void reset(scope const(ubyte)[] source) scope @trusted
    {
        ubyte* next;
        if (source.length != 0)
        {
            next = cast(ubyte*) malloc(source.length);
            if (next is null)
                onOutOfMemoryError();

            next[0 .. source.length] = source[];
        }

        clear();
        data_ = next;
        length_ = source.length;
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
