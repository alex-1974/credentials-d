/**
 * Operating-system cryptographic randomness for internal record locators.
 */
module credentials.random;

version (linux)
{
    import core.stdc.errno : EINTR, errno;
    import core.sys.posix.sys.types : ssize_t;

    extern(C) @nogc nothrow
    ssize_t getrandom(void* buffer, size_t length, uint flags);
}
else version (Windows)
{
    pragma(lib, "bcrypt");

    import core.sys.windows.bcrypt :
        BCryptGenRandom,
        BCRYPT_SUCCESS,
        BCRYPT_USE_SYSTEM_PREFERRED_RNG;
}
else version (OSX)
{
    extern(C) @nogc nothrow
    void arc4random_buf(void* buffer, size_t length);
}

/**
 * Fill `output` from the operating system CSPRNG.
 *
 * No deterministic or non-cryptographic fallback is permitted.
 */
package(credentials) bool secureRandomBytes(scope ubyte[] output)
    @trusted
{
    if (output.length == 0)
        return true;

    version (linux)
    {
        size_t offset;

        while (offset < output.length)
        {
            const count = getrandom(
                output.ptr + offset,
                output.length - offset,
                0
            );

            if (count < 0)
            {
                if (errno == EINTR)
                    continue;

                return false;
            }

            if (count == 0)
                return false;

            offset += cast(size_t) count;
        }

        return true;
    }
    else version (Windows)
    {
        if (output.length > uint.max)
            return false;

        const status = BCryptGenRandom(
            null,
            output.ptr,
            cast(uint) output.length,
            BCRYPT_USE_SYSTEM_PREFERRED_RNG
        );

        return BCRYPT_SUCCESS(status);
    }
    else version (OSX)
    {
        arc4random_buf(output.ptr, output.length);
        return true;
    }
    else
    {
        return false;
    }
}

/**
 * Generate a 128-bit non-secret locator encoded as 32 lowercase hex digits.
 */
package(credentials) bool generateSecureLocator(out string locator)
    @safe
{
    ubyte[16] random;

    if (!secureRandomBytes(random[]))
    {
        locator = null;
        return false;
    }

    static immutable char[16] hex = "0123456789abcdef";
    char[32] encoded;

    foreach (i, value; random)
    {
        encoded[i * 2] = hex[value >> 4];
        encoded[i * 2 + 1] = hex[value & 0x0F];
    }

    locator = encoded[].idup;
    return true;
}

@("secure record locators are bounded lowercase hex")
unittest
{
    string locator;
    assert(generateSecureLocator(locator));
    assert(locator.length == 32);

    foreach (char c; locator)
    {
        assert(
            (c >= '0' && c <= '9') ||
            (c >= 'a' && c <= 'f')
        );
    }
}
