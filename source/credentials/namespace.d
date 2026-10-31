/**
 * Application namespaces used to keep credential sets separate.
 */
module credentials.namespace;

/**
 * Stable name for one application's credential domain.
 *
 * Use a reverse-DNS-style value and keep it stable across application runs.
 * Different namespaces intentionally cannot use each other's handles.
 *
 * Examples:
 * ---
 * auto ns = CredentialNamespace("org.example.application");
 * auto store = new LinuxCredentialStore(ns);
 * ---
 */
struct CredentialNamespace
{
    private string value_;

    /**
     * Create the namespace used by application code.
     *
     * Use this constructor for a namespace literal or trusted configuration.
     * Use tryParse() when the text came from persisted or external input.
     *
     * Params:
     *     text = Stable lowercase reverse-DNS-style name.
     *
     * Throws:
     *     Exception when text is invalid.
     *
     * Examples:
     * ---
     * auto ns = CredentialNamespace("org.example.dunia");
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
     * Whether this value contains a usable namespace.
     */
    @property bool valid() const @nogc nothrow pure @safe
    {
        return value_.length != 0;
    }

    /**
     * Return the namespace text for persistence or display in diagnostics.
     */
    string serialize() const @nogc nothrow pure @safe
    {
        return value_;
    }

    /**
     * Restore or validate a namespace without throwing.
     *
     * Params:
     *     text = Namespace text read from settings or external input.
     *     result = Receives the namespace on success.
     *
     * Returns:
     *     true when text is valid; false otherwise.
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
