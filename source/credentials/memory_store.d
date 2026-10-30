/**
 * Ephemeral in-memory credential store.
 */
module credentials.memory_store;

import credentials.handle : CredentialHandle;
import credentials.secret : SecretBuffer;
import credentials.store :
    CredentialStatus,
    CredentialStore,
    SecretVisitor,
    StoreCapabilities,
    StoreConcurrency;
import std.format : format;

/**
 * Deterministic, thread-confined in-memory credential store.
 *
 * This backend exists for contract qualification, tests, examples, and
 * consumers that explicitly need ephemeral credentials. It is not a secure
 * persistent store and does not provide locking.
 */
final class MemoryCredentialStore : CredentialStore
{
    private ubyte[][string] records_;
    private ulong nextId_ = 1;

    ~this() @safe
    {
        foreach (ref bytes; records_)
            wipe(bytes);
        records_ = null;
    }

    override @property StoreCapabilities capabilities() const
        @nogc nothrow @safe
    {
        return StoreCapabilities(
            false, // persistent
            false, // supportsLocking
            false, // applicationControlledUnlock
            false, // userPresence
            false, // hardwareBacked
            false, // nativeOsStore
            true,  // confirmsLogicalDeletion
            StoreConcurrency.threadConfined
        );
    }

    override CredentialStatus store(
        scope SecretBuffer secret,
        out CredentialHandle handle
    ) @safe
    {
        handle = CredentialHandle.init;

        if (secret is null)
            return CredentialStatus.invalidInput;

        if (nextId_ == 0)
            return CredentialStatus.backendError;

        const serialized = format("memory:%016x", nextId_);
        ++nextId_;

        records_[serialized] = secret.duplicateBytes();
        handle = CredentialHandle.trusted(serialized);
        return CredentialStatus.ok;
    }

    override CredentialStatus acquire(
        CredentialHandle handle,
        scope SecretVisitor visitor
    ) @safe
    {
        if (!handle.valid || visitor is null)
            return CredentialStatus.invalidInput;

        auto record = handle.serialize() in records_;
        if (record is null)
            return CredentialStatus.notFound;

        visitor(*record);
        return CredentialStatus.ok;
    }

    override CredentialStatus replace(
        CredentialHandle handle,
        scope SecretBuffer replacement
    ) @safe
    {
        if (!handle.valid || replacement is null)
            return CredentialStatus.invalidInput;

        auto record = handle.serialize() in records_;
        if (record is null)
            return CredentialStatus.notFound;

        // Allocate the replacement before destroying the current record so an
        // allocation failure leaves the existing credential intact.
        ubyte[] next = replacement.duplicateBytes();

        wipe(*record);
        *record = next;
        return CredentialStatus.ok;
    }

    override CredentialStatus remove(CredentialHandle handle) @safe
    {
        if (!handle.valid)
            return CredentialStatus.invalidInput;

        const key = handle.serialize();
        auto record = key in records_;
        if (record is null)
            return CredentialStatus.notFound;

        wipe(*record);
        records_.remove(key);
        return CredentialStatus.ok;
    }

    private static void wipe(ref ubyte[] bytes) @safe
    {
        foreach (ref value; bytes)
            value = 0;
        bytes = null;
    }
}

@("MemoryCredentialStore lifecycle")
unittest
{
    auto store = new MemoryCredentialStore;
    auto first = new SecretBuffer(cast(const(ubyte)[]) "alpha");

    CredentialHandle handle;
    assert(store.store(first, handle) == CredentialStatus.ok);
    assert(handle.valid);

    bool acquired;
    assert(store.acquire(handle, (scope const(ubyte)[] bytes) @safe
    {
        assert(bytes == cast(const(ubyte)[]) "alpha");
        acquired = true;
    }) == CredentialStatus.ok);
    assert(acquired);

    auto second = new SecretBuffer(cast(const(ubyte)[]) "beta");
    assert(store.replace(handle, second) == CredentialStatus.ok);

    assert(store.acquire(handle, (scope const(ubyte)[] bytes) @safe
    {
        assert(bytes == cast(const(ubyte)[]) "beta");
    }) == CredentialStatus.ok);

    assert(store.remove(handle) == CredentialStatus.ok);
    assert(store.acquire(handle, (scope const(ubyte)[]) @safe {}) ==
        CredentialStatus.notFound);
    assert(store.remove(handle) == CredentialStatus.notFound);
}
