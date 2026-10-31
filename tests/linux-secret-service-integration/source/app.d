module app;

version (linux):

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
import credentials.backend.secret_service : LinuxSecretServiceStore;

private CredentialNamespace namespaceOf(string value)
{
    CredentialNamespace ns;
    assert(CredentialNamespace.tryParse(value, ns));
    return ns;
}

private void expectUnavailable()
{
    auto ns = namespaceOf("org.alex1974.credentials-unavailable");
    auto store = new LinuxSecretServiceStore(ns);
    scope(exit) store.close();

    auto secret = SecretBuffer(cast(const(ubyte)[]) "unavailable-test");

    CredentialHandle handle;
    assert(store.save(secret, handle) == CredentialStatus.unavailable);
    assert(!handle.valid);
}

private void runIntegration()
{
    auto ns = namespaceOf("org.alex1974.credentials-integration");
    auto store = new LinuxSecretServiceStore(ns);
    scope(exit) store.close();

    const capabilities = store.capabilities;
    assert(capabilities.persistent);
    assert(capabilities.protection ==
        StoreProtection.operatingSystem);
    assert(capabilities.unlockModel == StoreUnlockModel.operatingSystem);
    assert(capabilities.mobility == StoreMobility.mayRoam);
    assert(capabilities.blocking == StoreBlocking.mayPrompt);
    assert(capabilities.concurrency == StoreConcurrency.serialized);

    // Embedded NUL proves that this path is binary and length-delimited.
    ubyte[] firstBytes = [
        0x4c, 0x49, 0x4e, 0x55, 0x58,
        0x00,
        0x53, 0x45, 0x43, 0x52, 0x45, 0x54
    ];
    auto first = SecretBuffer(firstBytes);

    CredentialHandle handle;
    assert(store.save(first, handle) == CredentialStatus.ok);
    assert(handle.valid);

    scope(exit)
    {
        if (handle.valid)
            store.remove(handle);
    }

    bool acquired;
    assert(store.withSecret(handle, (scope const(ubyte)[] bytes) @safe
    {
        assert(bytes == firstBytes);
        acquired = true;
    }) == CredentialStatus.ok);
    assert(acquired);

    // A new backend instance with the same namespace must resolve the
    // persistent opaque handle.
    auto reopened = new LinuxSecretServiceStore(ns);
    scope(exit) reopened.close();

    assert(reopened.withSecret(handle, (scope const(ubyte)[] bytes) @safe
    {
        assert(bytes == firstBytes);
    }) == CredentialStatus.ok);

    ubyte[] replacementBytes = [
        0x52, 0x45, 0x50, 0x4c, 0x41, 0x43, 0x45,
        0x00,
        0x44
    ];
    auto replacement = SecretBuffer(replacementBytes);

    assert(reopened.update(handle, replacement) ==
        CredentialStatus.ok);

    assert(store.withSecret(handle, (scope const(ubyte)[] bytes) @safe
    {
        assert(bytes == replacementBytes);
    }) == CredentialStatus.ok);

    // A different application namespace must fail before native lookup.
    auto otherNs = namespaceOf("org.alex1974.credentials-other");
    auto otherStore = new LinuxSecretServiceStore(otherNs);
    scope(exit) otherStore.close();

    bool wrongNamespaceCalled;
    assert(otherStore.withSecret(
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
    assert(reopened.withSecret(
        deletedHandle,
        (scope const(ubyte)[]) @safe
        {
            calledAfterDelete = true;
        }
    ) == CredentialStatus.notFound);
    assert(!calledAfterDelete);
}

void main(string[] args)
{
    if (args.length == 2 && args[1] == "--expect-unavailable")
    {
        expectUnavailable();
        return;
    }

    runIntegration();
}
