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
    SecretCallback,
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

    CredentialStatus forcedSaveStatus = CredentialStatus.ok;
    CredentialStatus forcedWithSecretStatus = CredentialStatus.ok;
    CredentialStatus forcedUpdateStatus = CredentialStatus.ok;
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

    override CredentialStatus save(
        scope ref const SecretBuffer secret,
        out CredentialHandle handle
    ) @safe
    {
        if (forcedSaveStatus != CredentialStatus.ok)
        {
            handle = CredentialHandle.init;
            return forcedSaveStatus;
        }

        return inner_.save(secret, handle);
    }

    override CredentialStatus withSecret(
        CredentialHandle handle,
        scope SecretCallback visitor
    ) @safe
    {
        if (forcedWithSecretStatus != CredentialStatus.ok)
            return forcedWithSecretStatus;

        return inner_.withSecret(handle, visitor);
    }

    override CredentialStatus update(
        CredentialHandle handle,
        scope ref const SecretBuffer replacement
    ) @safe
    {
        if (forcedUpdateStatus != CredentialStatus.ok)
            return forcedUpdateStatus;

        return inner_.update(handle, replacement);
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
    assert(store.save(secret, handle) == CredentialStatus.ok);

    store.forcedWithSecretStatus = CredentialStatus.locked;

    bool called;
    const status = store.withSecret(handle, (scope const(ubyte)[]) @safe
    {
        called = true;
    });

    assert(status == CredentialStatus.locked);
    assert(!called);
}
