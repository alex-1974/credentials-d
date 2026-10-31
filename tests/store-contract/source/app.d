module app;

import credentials :
    CredentialHandle,
    CredentialNamespace,
    CredentialStatus,
    CredentialStore,
    MemoryCredentialStore,
    SecretBuffer,
    StoreBlocking,
    StoreConcurrency,
    StoreMobility,
    StoreProtection,
    StoreUnlockModel;
import credentials.testing : MockCredentialStore;

private CredentialNamespace testNamespace()
{
    CredentialNamespace ns;
    assert(CredentialNamespace.tryParse("org.example.credentials-contract", ns));
    return ns;
}

private void runStoreContract(CredentialStore store)
{
    assert(store.credentialNamespace == testNamespace());

    const capabilities = store.capabilities;
    assert(capabilities.protection == StoreProtection.memoryOnly);
    assert(capabilities.unlockModel == StoreUnlockModel.none);
    assert(capabilities.mobility == StoreMobility.processOnly);
    assert(capabilities.blocking == StoreBlocking.nonBlocking);
    assert(capabilities.concurrency == StoreConcurrency.threadConfined);

    auto first = SecretBuffer(cast(const(ubyte)[]) "contract:first");

    CredentialHandle handle;
    assert(store.save(first, handle) == CredentialStatus.ok);
    assert(handle.valid);

    CredentialHandle parsed;
    assert(CredentialHandle.tryParse(handle.serialize(), parsed));
    assert(parsed.serialize() == handle.serialize());

    size_t visits;
    assert(store.withSecret(parsed, (scope const(ubyte)[] bytes) @safe
    {
        assert(bytes == cast(const(ubyte)[]) "contract:first");
        ++visits;
    }) == CredentialStatus.ok);
    assert(visits == 1);

    auto replacement =
        SecretBuffer(cast(const(ubyte)[]) "contract:second");
    assert(store.update(parsed, replacement) == CredentialStatus.ok);

    assert(store.withSecret(parsed, (scope const(ubyte)[] bytes) @safe
    {
        assert(bytes == cast(const(ubyte)[]) "contract:second");
        ++visits;
    }) == CredentialStatus.ok);
    assert(visits == 2);

    assert(store.remove(parsed) == CredentialStatus.ok);

    bool calledAfterRemove;
    assert(store.withSecret(parsed, (scope const(ubyte)[]) @safe
    {
        calledAfterRemove = true;
    }) == CredentialStatus.notFound);
    assert(!calledAfterRemove);

    assert(store.update(parsed, replacement) == CredentialStatus.notFound);
    assert(store.remove(parsed) == CredentialStatus.notFound);
}

void main()
{
    auto ns = testNamespace();

    auto memory = new MemoryCredentialStore(ns);
    scope(exit) memory.clearAll();
    runStoreContract(memory);

    auto mock = new MockCredentialStore(ns);
    scope(exit) mock.clearAll();
    runStoreContract(mock);

    auto locked = new MockCredentialStore(ns);
    scope(exit) locked.clearAll();

    auto secret = SecretBuffer(cast(const(ubyte)[]) "locked-test");

    CredentialHandle handle;
    assert(locked.save(secret, handle) == CredentialStatus.ok);

    locked.forcedWithSecretStatus = CredentialStatus.locked;

    bool called;
    assert(locked.withSecret(handle, (scope const(ubyte)[]) @safe
    {
        called = true;
    }) == CredentialStatus.locked);
    assert(!called);

    auto unavailable = new MockCredentialStore(ns);
    scope(exit) unavailable.clearAll();
    unavailable.forcedSaveStatus = CredentialStatus.unavailable;

    CredentialHandle unavailableHandle;
    assert(unavailable.save(secret, unavailableHandle) ==
        CredentialStatus.unavailable);
    assert(!unavailableHandle.valid);
}
