/**
 * Retained unlocked-vault key state.
 */
module credentials.backend.vault.session;

import credentials.secret : SecretBuffer;

package(credentials.backend.vault):

alias VaultKeyVisitor =
    void delegate(scope const(ubyte)[] key) @safe;

/**
 * Holds only the random vault key for an unlocked session.
 *
 * The user's passphrase is never retained. The key bytes live in
 * SecretBuffer's non-GC allocation and are explicitly cleared by lock().
 *
 * Because this object is GC-managed, consumers must not rely on class
 * finalization for prompt key destruction. EncryptedVaultCredentialStore
 * exposes explicit lock() and calls it from its own best-effort destructor.
 */
final class VaultSession
{
    private SecretBuffer key_;
    private ubyte[16] vaultId_;
    private bool unlocked_;

    @property bool unlocked() const scope @nogc nothrow @safe
    {
        return unlocked_;
    }

    void set(
        scope const(ubyte)[] key,
        scope const ubyte[16] vaultId
    ) @safe
    {
        key_.reset(key);
        vaultId_[] = vaultId[];
        unlocked_ = true;
    }

    void clear() @safe
    {
        key_.clear();
        vaultId_[] = 0;
        unlocked_ = false;
    }

    bool matchesVault(scope const ubyte[16] vaultId) const scope
        @nogc nothrow @safe
    {
        if (!unlocked_)
            return false;

        return vaultId_ == vaultId;
    }

    string vaultIdText() const scope @safe
    in (unlocked_)
    {
        enum string digits = "0123456789abcdef";
        char[32] encoded;

        foreach (i, value; vaultId_)
        {
            encoded[i * 2] = digits[value >> 4];
            encoded[i * 2 + 1] = digits[value & 0x0f];
        }

        return encoded[].idup;
    }

    void withKey(scope VaultKeyVisitor visitor) const scope @safe
    in (visitor !is null)
    in (unlocked_)
    {
        key_.withBytes(visitor);
    }

    ~this() @safe
    {
        clear();
    }
}
