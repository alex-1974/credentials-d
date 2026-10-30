module app;

version (OSX):

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
import credentials.backend.macos :
    MacOSDataProtectionCredentialStore;

private CredentialNamespace namespaceOf(string value)
{
    CredentialNamespace ns;
    assert(CredentialNamespace.tryParse(value, ns));
    return ns;
}

void main()
{
    auto ns = namespaceOf("org.alex1974.credentials-integration");
    auto store = new MacOSDataProtectionCredentialStore(ns);

    const capabilities = store.capabilities;
    assert(capabilities.persistent);
    assert(capabilities.protection ==
        StoreProtection.nativeUserCredentialStore);
    assert(capabilities.unlockModel == StoreUnlockModel.osManaged);
    assert(capabilities.mobility == StoreMobility.localDevice);
    assert(capabilities.blocking == StoreBlocking.mayBlock);
    assert(capabilities.concurrency == StoreConcurrency.serialized);

    ubyte[] firstBytes = [
        0x4d, 0x41, 0x43, 0x4f, 0x53,
        0x00,
        0x53, 0x45, 0x43, 0x52, 0x45, 0x54
    ];
    auto first = SecretBuffer(firstBytes);

    CredentialHandle handle;
    const stored = store.store(first, handle);

    // GitHub-hosted macOS runners are not provisioned with the application's
    // production keychain-access entitlement. In that execution context the
    // security property under test is fail-closed behavior with no legacy
    // keychain fallback.
    if (stored == CredentialStatus.permissionDenied ||
        stored == CredentialStatus.unavailable)
    {
        assert(!handle.valid);
        return;
    }

    // A suitably signed execution environment gets the complete integration
    // qualification below.
    assert(stored == CredentialStatus.ok);
    assert(handle.valid);

    scope(exit)
    {
        if (handle.valid)
            store.remove(handle);
    }

    bool acquired;
    assert(store.acquire(handle, (scope const(ubyte)[] bytes) @safe
    {
        assert(bytes == firstBytes);
        acquired = true;
    }) == CredentialStatus.ok);
    assert(acquired);

    auto reopened = new MacOSDataProtectionCredentialStore(ns);
    assert(reopened.acquire(handle, (scope const(ubyte)[] bytes) @safe
    {
        assert(bytes == firstBytes);
    }) == CredentialStatus.ok);

    ubyte[] replacementBytes = [
        0x52, 0x45, 0x50, 0x4c, 0x41, 0x43, 0x45,
        0x00,
        0x44
    ];
    auto replacement = SecretBuffer(replacementBytes);

    assert(reopened.replace(handle, replacement) ==
        CredentialStatus.ok);

    assert(store.acquire(handle, (scope const(ubyte)[] bytes) @safe
    {
        assert(bytes == replacementBytes);
    }) == CredentialStatus.ok);

    auto otherNs = namespaceOf("org.alex1974.credentials-other");
    auto otherStore =
        new MacOSDataProtectionCredentialStore(otherNs);

    bool wrongNamespaceCalled;
    assert(otherStore.acquire(
        handle,
        (scope const(ubyte)[]) @safe
        {
            wrongNamespaceCalled = true;
        }
    ) == CredentialStatus.invalidInput);
    assert(!wrongNamespaceCalled);

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
