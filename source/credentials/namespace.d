/**
 * Application credential namespaces.
 */
module credentials.namespace;

/**
 * Validated, non-secret namespace used to isolate one consumer's credentials.
 *
 * Reverse-DNS names are recommended, for example
 * `org.example.application`. Names are canonical lowercase ASCII and are
 * safe to persist in ordinary configuration.
 */
struct CredentialNamespace
{
    private string value_;

    /**
     * Construct an application namespace from trusted configuration.
     *
     * Use tryParse() when reading namespace text from persisted or otherwise
     * untrusted input.
     *
     * Params:
     *     text = Canonical lowercase reverse-DNS-style namespace.
     *
     * Throws:
     *     Exception when text is not a valid credential namespace.
     *
     * Examples:
     * ---
     * auto ns = CredentialNamespace("org.example.dunia");
     * assert(ns.serialize() == "org.example.dunia");
     * ---
     */
    this(string text) @safe
    {
        CredentialNamespace parsed;
        if (!tryParse(text, parsed))
            throw new Exception("invalid credential namespace");

        value_ = parsed.value_;
    }

    /**
     * Whether this namespace contains a valid canonical value.
     */
    @property bool valid() const @nogc nothrow pure @safe
    {
        return value_.length != 0;
    }

    /**
     * Return the canonical non-secret namespace text.
     */
    string serialize() const @nogc nothrow pure @safe
    {
        return value_;
    }

    /**
     * Parse a canonical credential namespace without throwing.
     *
     * Each dot-separated segment may contain lowercase ASCII letters, digits
     * and interior hyphens. Empty segments and leading/trailing hyphens are
     * rejected. The maximum length is deliberately bounded.
     *
     * Params:
     *     text = Candidate namespace text.
     *     result = Receives the parsed namespace on success, otherwise init.
     *
     * Returns:
     *     true when text is valid and canonical; false otherwise.
     */
    static bool tryParse(string text, out CredentialNamespace result)
        @nogc nothrow pure @safe
    {
        result = CredentialNamespace.init;

        if (text.length == 0 || text.length > 96)
            return false;

        bool segmentStart = true;
        bool previousHyphen;

        foreach (char c; text)
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

        if (segmentStart || previousHyphen)
            return false;

        result.value_ = text;
        return true;
    }
}

@("CredentialNamespace accepts canonical application namespaces")
unittest
{
    CredentialNamespace ns;
    assert(CredentialNamespace.tryParse("org.example.dunia", ns));
    assert(ns.valid);
    assert(ns.serialize() == "org.example.dunia");
}

@("CredentialNamespace rejects ambiguous or non-canonical forms")
unittest
{
    CredentialNamespace ns;

    assert(!CredentialNamespace.tryParse("", ns));
    assert(!CredentialNamespace.tryParse(".org.example", ns));
    assert(!CredentialNamespace.tryParse("org..example", ns));
    assert(!CredentialNamespace.tryParse("org.example.", ns));
    assert(!CredentialNamespace.tryParse("Org.Example", ns));
    assert(!CredentialNamespace.tryParse("org.-example", ns));
    assert(!CredentialNamespace.tryParse("org.example-", ns));
    assert(!CredentialNamespace.tryParse("org/example", ns));
}
