/**
 * Deterministic test doubles for credential-store consumers.
 */
module credentials.testing;

import credentials.handle : CredentialHandle;
import credentials.memory_store : MemoryCredentialStore;
import credentials.namespace : CredentialNamespace;
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
 * operation class to return statuses such as `locked`, `unavailable`, or
 * `backendFailure` without invoking the corresponding plaintext callback.
 */
final class MockCredentialStore : CredentialStore
{
    private MemoryCredentialStore inner_;

    CredentialStatus forcedStoreStatus = CredentialStatus.ok;
    CredentialStatus forcedAcquireStatus = CredentialStatus.ok;
    CredentialStatus forcedReplaceStatus = CredentialStatus.ok;
    CredentialStatus forcedRemoveStatus = CredentialStatus.ok;

    this(CredentialNamespace credentialNamespace) @safe
    in (credentialNamespace.valid)
    {
        inner_ = new MemoryCredentialStore(credentialNamespace);
    }

    override @property CredentialNamespace credentialNamespace() const
        @nogc nothrow @safe
    {
        return inner_.credentialNamespace;
    }

    override @property StoreCapabilities capabilities() const
        @nogc nothrow @safe
    {
        return inner_.capabilities;
    }

    override CredentialStatus store(
        scope ref const SecretBuffer secret,
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
        scope ref const SecretBuffer replacement
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

    /**
     * Promptly wipe all records retained by the underlying memory backend.
     */
    void clearAll() @safe
    {
        inner_.clearAll();
    }
}

@("MockCredentialStore can model a locked acquisition")
unittest
{
    CredentialNamespace ns;
    assert(CredentialNamespace.tryParse("org.example.credentials-test", ns));

    auto store = new MockCredentialStore(ns);
    scope(exit) store.clearAll();

    auto secret = SecretBuffer(cast(const(ubyte)[]) "alpha");

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
