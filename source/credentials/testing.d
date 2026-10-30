/**
 * Deterministic test doubles for credential-store consumers.
 */
module credentials.testing;

import credentials.handle : CredentialHandle;
import credentials.memory_store : MemoryCredentialStore;
import credentials.secret : SecretBuffer;
import credentials.store :
    CredentialStatus,
    CredentialStore,
    SecretVisitor,
    StoreCapabilities;

/**
 * Credential-store mock with deterministic forced-status hooks.
 *
 * Normal operations delegate to `MemoryCredentialStore`. Tests can force one
 * operation class to return `locked`, `unsupported`, or `backendError`
 * without invoking the corresponding plaintext callback.
 */
final class MockCredentialStore : CredentialStore
{
    private MemoryCredentialStore inner_;

    CredentialStatus forcedStoreStatus = CredentialStatus.ok;
    CredentialStatus forcedAcquireStatus = CredentialStatus.ok;
    CredentialStatus forcedReplaceStatus = CredentialStatus.ok;
    CredentialStatus forcedRemoveStatus = CredentialStatus.ok;

    this() @safe
    {
        inner_ = new MemoryCredentialStore;
    }

    override @property StoreCapabilities capabilities() const
        @nogc nothrow @safe
    {
        return inner_.capabilities;
    }

    override CredentialStatus store(
        scope SecretBuffer secret,
        out CredentialHandle handle
    ) @safe
    {
        if (forcedStoreStatus != CredentialStatus.ok)
        {
            handle = CredentialHandle.init;
            return forcedStoreStatus;
        }

        return inner_.store(secret, handle);
    }

    override CredentialStatus acquire(
        CredentialHandle handle,
        scope SecretVisitor visitor
    ) @safe
    {
        if (forcedAcquireStatus != CredentialStatus.ok)
            return forcedAcquireStatus;

        return inner_.acquire(handle, visitor);
    }

    override CredentialStatus replace(
        CredentialHandle handle,
        scope SecretBuffer replacement
    ) @safe
    {
        if (forcedReplaceStatus != CredentialStatus.ok)
            return forcedReplaceStatus;

        return inner_.replace(handle, replacement);
    }

    override CredentialStatus remove(CredentialHandle handle) @safe
    {
        if (forcedRemoveStatus != CredentialStatus.ok)
            return forcedRemoveStatus;

        return inner_.remove(handle);
    }
}

@("MockCredentialStore can model a locked acquisition")
unittest
{
    auto store = new MockCredentialStore;
    auto secret = new SecretBuffer(cast(const(ubyte)[]) "alpha");

    CredentialHandle handle;
    assert(store.store(secret, handle) == CredentialStatus.ok);

    store.forcedAcquireStatus = CredentialStatus.locked;

    bool called;
    const status = store.acquire(handle, (scope const(ubyte)[]) @safe
    {
        called = true;
    });

    assert(status == CredentialStatus.locked);
    assert(!called);
}
