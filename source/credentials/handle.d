/**
 * Persistable opaque credential handles.
 */
module credentials.handle;

/**
 * Non-secret reference to a credential record.
 *
 * Handles returned by credentials-d contain no credential plaintext and are
 * intended to be safe to persist in ordinary application settings.
 *
 * The serialized form is opaque to consumers. Consumers may persist it and
 * later reconstruct a handle with `tryParse`, but must not infer backend,
 * namespace, identity or authorization semantics from its contents.
 */
struct CredentialHandle
{
    private string value_;

    /**
     * Whether this handle contains a non-empty serialized identifier.
     */
    @property bool valid() const @nogc nothrow pure @safe
    {
        return value_.length != 0;
    }

    /**
     * Return the opaque serialized representation for persistence.
     */
    string serialize() const @nogc nothrow pure @safe
    {
        return value_;
    }

    /**
     * Parse a serialized handle previously returned by credentials-d.
     *
     * The grammar is deliberately narrow and bounded to keep handles
     * single-line and suitable for ordinary configuration stores.
     */
    static bool tryParse(string text, out CredentialHandle handle)
        @nogc nothrow pure @safe
    {
        handle = CredentialHandle.init;

        if (text.length == 0 || text.length > 256)
            return false;

        foreach (char c; text)
        {
            const allowed =
                (c >= 'a' && c <= 'z') ||
                (c >= 'A' && c <= 'Z') ||
                (c >= '0' && c <= '9') ||
                c == '.' || c == '_' || c == ':' || c == '-';

            if (!allowed)
                return false;
        }

        handle.value_ = text;
        return true;
    }

    /**
     * Construct a trusted handle from a backend-controlled serialized value.
     */
    package(credentials) static CredentialHandle trusted(string text)
        @nogc nothrow pure @safe
    {
        CredentialHandle handle;
        handle.value_ = text;
        return handle;
    }

    /**
     * Whether this handle belongs to the backend-controlled store prefix.
     *
     * This helper is package-private so consumers cannot use handle internals
     * as application identity or authorization data.
     */
    package(credentials) bool hasStorePrefix(string prefix) const
        @nogc nothrow pure @safe
    {
        return value_.length > prefix.length &&
            value_[0 .. prefix.length] == prefix;
    }
}

@("CredentialHandle round-trips through ordinary text")
unittest
{
    CredentialHandle original =
        CredentialHandle.trusted("cred1:org.example.app:memory:0001:0001");

    CredentialHandle parsed;
    assert(CredentialHandle.tryParse(original.serialize(), parsed));
    assert(parsed.serialize() == original.serialize());
    assert(parsed.valid);
}

@("CredentialHandle rejects unsafe serialized forms")
unittest
{
    CredentialHandle handle;

    assert(!CredentialHandle.tryParse("", handle));
    assert(!CredentialHandle.tryParse("contains space", handle));
    assert(!CredentialHandle.tryParse("contains\nnewline", handle));
    assert(!CredentialHandle.tryParse("contains/slash", handle));
}
