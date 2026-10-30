/**
 * Narrow private libsodium ABI used by the encrypted-vault backend.
 *
 * This module intentionally does not expose a general-purpose crypto API.
 */
module credentials.backend.vault.sodium;

package(credentials.backend.vault):

extern(C) @nogc nothrow
{
    int sodium_init();
    const(char)* sodium_version_string();
    void sodium_memzero(void* pnt, size_t len);
    void randombytes_buf(void* buf, size_t size);

    size_t crypto_pwhash_saltbytes();
    int crypto_pwhash_alg_argon2id13();

    int crypto_pwhash(
        ubyte* out_,
        ulong outlen,
        const(char)* passwd,
        ulong passwdlen,
        const(ubyte)* salt,
        ulong opslimit,
        size_t memlimit,
        int alg
    );

    size_t crypto_aead_xchacha20poly1305_ietf_keybytes();
    size_t crypto_aead_xchacha20poly1305_ietf_npubbytes();
    size_t crypto_aead_xchacha20poly1305_ietf_abytes();

    int crypto_aead_xchacha20poly1305_ietf_encrypt(
        ubyte* c,
        ulong* clen_p,
        const(ubyte)* m,
        ulong mlen,
        const(ubyte)* ad,
        ulong adlen,
        const(ubyte)* nsec,
        const(ubyte)* npub,
        const(ubyte)* k
    );

    int crypto_aead_xchacha20poly1305_ietf_decrypt(
        ubyte* m,
        ulong* mlen_p,
        ubyte* nsec,
        const(ubyte)* c,
        ulong clen,
        const(ubyte)* ad,
        ulong adlen,
        const(ubyte)* npub,
        const(ubyte)* k
    );
}

enum size_t vaultKeyBytes = 32;
enum size_t pwhashSaltBytes = 16;
enum size_t xNonceBytes = 24;
enum size_t aeadTagBytes = 16;

/**
 * Initialize and qualify the exact libsodium primitive ABI required here.
 */
bool sodiumReady() @trusted
{
    if (sodium_init() < 0)
        return false;

    if (sodium_version_string() is null)
        return false;

    return
        crypto_pwhash_saltbytes() == pwhashSaltBytes &&
        crypto_pwhash_alg_argon2id13() > 0 &&
        crypto_aead_xchacha20poly1305_ietf_keybytes() == vaultKeyBytes &&
        crypto_aead_xchacha20poly1305_ietf_npubbytes() == xNonceBytes &&
        crypto_aead_xchacha20poly1305_ietf_abytes() == aeadTagBytes;
}

void zero(scope ubyte[] bytes) @trusted
{
    if (bytes.length != 0)
        sodium_memzero(bytes.ptr, bytes.length);
}

void zeroFixed(size_t N)(ref ubyte[N] bytes) @trusted
{
    static if (N != 0)
        sodium_memzero(bytes.ptr, N);
}
