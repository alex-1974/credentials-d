/**
 * Ephemeral in-memory credential store.
 */
module credentials.memory_store;

import core.atomic : atomicFetchAdd;
import core.volatile : volatileStore;
import credentials.handle : CredentialHandle;
import credentials.namespace : CredentialNamespace;
import credentials.secret : SecretBuffer;
import credentials.store :
    CredentialStatus,
    CredentialStore,
    SecretCallback,
    StoreBlocking,
    StoreCapabilities,
    StoreConcurrency,
    StoreMobility,
    StoreProtection,
    StoreUnlockModel;
import std.format : format;

private shared ulong nextMemoryStoreInstanceId;

/**
 * Deterministic, thread-confined in-memory credential store.
 *
 * This backend exists for contract qualification, tests, examples, and
 * consumers that explicitly need ephemeral credentials. It is not a secure
 * persistent store and does not provide locking.
 *
 * Call `clearAll` when prompt wiping of all retained test credentials is
 * required. The backend deliberately does not rely on a GC class finalizer to
 * traverse GC-managed associative-array state.
 */
final class MemoryCredentialStore : CredentialStore
{
    private CredentialNamespace namespace_;
    private string storePrefix_;
    private ubyte[][string] records_;
    private ulong nextId_ = 1;

    /**
     * Bind this store instance to one validated application namespace.
     */
    this(CredentialNamespace credentialNamespace) @safe
    in (credentialNamespace.valid)
    {
        namespace_ = credentialNamespace;

        const instanceId =
            atomicFetchAdd(nextMemoryStoreInstanceId, cast(ulong) 1) + 1;

        storePrefix_ =
            "cred1:" ~ namespace_.serialize() ~ ":memory:" ~
            format("%016x:", instanceId);
    }

    override @property CredentialNamespace credentialNamespace() const
        @nogc nothrow @safe
    {
        return namespace_;
    }

    override @property StoreCapabilities capabilities() const
        @nogc nothrow @safe
    {
        return StoreCapabilities(
            false,
            StoreProtection.memoryOnly,
            StoreUnlockModel.none,
            false,
            StoreMobility.processOnly,
            true,
            StoreBlocking.nonBlocking,
            StoreConcurrency.threadConfined
        );
    }

    override CredentialStatus save(
        scope ref const SecretBuffer secret,
        out CredentialHandle handle
    ) @safe
    {
        handle = CredentialHandle.init;

        if (nextId_ == 0)
            return CredentialStatus.backendFailure;

        const serialized =
            storePrefix_ ~ format("%016x", nextId_);
        ++nextId_;

        records_[serialized] = copySecret(secret);
        handle = CredentialHandle.trusted(serialized);
        return CredentialStatus.ok;
    }

    override CredentialStatus withSecret(
        CredentialHandle handle,
        scope SecretCallback callback
    ) @safe
    {
        if (!handle.valid || callback is null)
            return CredentialStatus.invalidInput;

        if (!handle.hasStorePrefix(storePrefix_))
            return CredentialStatus.invalidInput;

        auto record = handle.serialize() in records_;
        if (record is null)
            return CredentialStatus.notFound;

        callback(*record);
        return CredentialStatus.ok;
    }

    override CredentialStatus update(
        CredentialHandle handle,
        scope ref const SecretBuffer replacement
    ) @safe
    {
        if (!handle.valid || !handle.hasStorePrefix(storePrefix_))
            return CredentialStatus.invalidInput;

        auto record = handle.serialize() in records_;
        if (record is null)
            return CredentialStatus.notFound;

        // Allocate the replacement before destroying the current record so an
        // allocation failure leaves the existing credential intact.
        ubyte[] next = copySecret(replacement);

        wipe(*record);
        *record = next;
        return CredentialStatus.ok;
    }

    override CredentialStatus remove(CredentialHandle handle) @safe
    {
        if (!handle.valid || !handle.hasStorePrefix(storePrefix_))
            return CredentialStatus.invalidInput;

        const key = handle.serialize();
        auto record = key in records_;
        if (record is null)
            return CredentialStatus.notFound;

        wipe(*record);
        records_.remove(key);
        return CredentialStatus.ok;
    }

    /**
     * Securely wipe all records currently retained by this test backend.
     */
    void clearAll() @safe
    {
        foreach (ref bytes; records_)
            wipe(bytes);

        records_ = null;
    }

    private static ubyte[] copySecret(
        scope ref const SecretBuffer secret
    ) @safe
    {
        ubyte[] copy;

        secret.withBytes((scope const(ubyte)[] bytes) @safe
        {
            copy = new ubyte[bytes.length];
            copy[] = bytes[];
        });

        return copy;
    }

    private static void wipe(ref ubyte[] bytes) @trusted
    {
        foreach (i; 0 .. bytes.length)
            volatileStore(bytes.ptr + i, cast(ubyte) 0);

        bytes = null;
    }
}

@("MemoryCredentialStore lifecycle")
unittest
{
    CredentialNamespace ns;
    assert(CredentialNamespace.tryParse("org.example.credentials-test", ns));

    auto store = new MemoryCredentialStore(ns);
    scope(exit) store.clearAll();

    auto first = SecretBuffer(cast(const(ubyte)[]) "alpha");

    CredentialHandle handle;
    assert(store.save(first, handle) == CredentialStatus.ok);
    assert(handle.valid);

    bool acquired;
    assert(store.withSecret(handle, (scope const(ubyte)[] bytes) @safe
    {
        assert(bytes == cast(const(ubyte)[]) "alpha");
        acquired = true;
    }) == CredentialStatus.ok);
    assert(acquired);

    auto second = SecretBuffer(cast(const(ubyte)[]) "beta");
    assert(store.update(handle, second) == CredentialStatus.ok);

    assert(store.withSecret(handle, (scope const(ubyte)[] bytes) @safe
    {
        assert(bytes == cast(const(ubyte)[]) "beta");
    }) == CredentialStatus.ok);

    assert(store.remove(handle) == CredentialStatus.ok);
    assert(store.withSecret(handle, (scope const(ubyte)[]) @safe {}) ==
        CredentialStatus.notFound);
    assert(store.remove(handle) == CredentialStatus.notFound);
}

@("MemoryCredentialStore rejects a handle from another store instance")
unittest
{
    CredentialNamespace ns;
    assert(CredentialNamespace.tryParse("org.example.credentials-test", ns));

    auto firstStore = new MemoryCredentialStore(ns);
    auto secondStore = new MemoryCredentialStore(ns);
    scope(exit)
    {
        firstStore.clearAll();
        secondStore.clearAll();
    }

    auto firstSecret = SecretBuffer(cast(const(ubyte)[]) "first");
    auto secondSecret = SecretBuffer(cast(const(ubyte)[]) "second");

    CredentialHandle firstHandle;
    CredentialHandle secondHandle;

    assert(firstStore.save(firstSecret, firstHandle) == CredentialStatus.ok);
    assert(secondStore.save(secondSecret, secondHandle) == CredentialStatus.ok);

    bool called;
    assert(secondStore.withSecret(firstHandle, (scope const(ubyte)[]) @safe
    {
        called = true;
    }) == CredentialStatus.invalidInput);
    assert(!called);
}
