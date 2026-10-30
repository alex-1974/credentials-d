module app;

version (Windows):

import credentials :
    CredentialHandle,
    CredentialNamespace,
    CredentialStatus,
    SecretBuffer,
    StoreBlocking,
    StoreConcurrency,
    StoreMobility,
    StoreProtection,
    StoreUnlockModel;
import credentials.backend.windows : WindowsCredentialStore;

private CredentialNamespace namespaceOf(string value)
{
    CredentialNamespace ns;
    assert(CredentialNamespace.tryParse(value, ns));
    return ns;
}

void main()
{
    auto ns = namespaceOf("org.alex1974.credentials-integration");
    auto store = new WindowsCredentialStore(ns);

    const capabilities = store.capabilities;
    assert(capabilities.persistent);
    assert(capabilities.protection ==
        StoreProtection.nativeUserCredentialStore);
    assert(capabilities.unlockModel == StoreUnlockModel.osManaged);
    assert(capabilities.mobility == StoreMobility.localDevice);
    assert(capabilities.blocking == StoreBlocking.mayBlock);
    assert(capabilities.concurrency == StoreConcurrency.serialized);

    auto first = SecretBuffer(
        cast(const(ubyte)[]) "WINDOWS_INTEGRATION_SENTINEL_ONE"
    );

    CredentialHandle handle;
    const storeStatus = store.store(first, handle);
    assert(storeStatus == CredentialStatus.ok);
    assert(handle.valid);

    scope(exit)
    {
        if (handle.valid)
            store.remove(handle);
    }

    bool acquired;
    assert(store.acquire(handle, (scope const(ubyte)[] bytes) @safe
    {
        assert(bytes ==
            cast(const(ubyte)[]) "WINDOWS_INTEGRATION_SENTINEL_ONE");
        acquired = true;
    }) == CredentialStatus.ok);
    assert(acquired);

    // A fresh backend instance with the same namespace must be able to use a
    // persisted handle.
    auto reopened = new WindowsCredentialStore(ns);
    assert(reopened.acquire(handle, (scope const(ubyte)[] bytes) @safe
    {
        assert(bytes ==
            cast(const(ubyte)[]) "WINDOWS_INTEGRATION_SENTINEL_ONE");
    }) == CredentialStatus.ok);

    auto replacement = SecretBuffer(
        cast(const(ubyte)[]) "WINDOWS_INTEGRATION_SENTINEL_TWO"
    );
    assert(reopened.replace(handle, replacement) ==
        CredentialStatus.ok);

    assert(store.acquire(handle, (scope const(ubyte)[] bytes) @safe
    {
        assert(bytes ==
            cast(const(ubyte)[]) "WINDOWS_INTEGRATION_SENTINEL_TWO");
    }) == CredentialStatus.ok);

    // A different application namespace must fail closed before native lookup.
    auto otherNs = namespaceOf("org.alex1974.credentials-other");
    auto otherStore = new WindowsCredentialStore(otherNs);

    bool wrongNamespaceCalled;
    assert(otherStore.acquire(
        handle,
        (scope const(ubyte)[]) @safe
        {
            wrongNamespaceCalled = true;
        }
    ) == CredentialStatus.invalidInput);
    assert(!wrongNamespaceCalled);

    // The Windows Generic Credential blob limit is enforced before FFI.
    ubyte[2561] oversizedBytes;
    auto oversized = SecretBuffer(oversizedBytes[]);

    CredentialHandle oversizedHandle;
    assert(store.store(oversized, oversizedHandle) ==
        CredentialStatus.tooLarge);
    assert(!oversizedHandle.valid);

    auto deletedHandle = handle;
    assert(store.remove(handle) == CredentialStatus.ok);
    handle = CredentialHandle.init;

    bool calledAfterDelete;
    assert(reopened.acquire(
        deletedHandle,
        (scope const(ubyte)[]) @safe
        {
            calledAfterDelete = true;
        }
    ) == CredentialStatus.notFound);
    assert(!calledAfterDelete);
}
