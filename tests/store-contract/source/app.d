module app;

import credentials :
    CredentialHandle,
    CredentialStatus,
    CredentialStore,
    MemoryCredentialStore,
    SecretBuffer,
    StoreConcurrency;
import credentials.testing : MockCredentialStore;

private void runStoreContract(CredentialStore store)
{
    assert(store.capabilities.concurrency == StoreConcurrency.threadConfined);

    auto first = new SecretBuffer(cast(const(ubyte)[]) "contract:first");

    CredentialHandle handle;
    assert(store.store(first, handle) == CredentialStatus.ok);
    assert(handle.valid);

    CredentialHandle parsed;
    assert(CredentialHandle.tryParse(handle.serialize(), parsed));
    assert(parsed.serialize() == handle.serialize());

    size_t visits;
    assert(store.acquire(parsed, (scope const(ubyte)[] bytes) @safe
    {
        assert(bytes == cast(const(ubyte)[]) "contract:first");
        ++visits;
    }) == CredentialStatus.ok);
    assert(visits == 1);

    auto replacement = new SecretBuffer(cast(const(ubyte)[]) "contract:second");
    assert(store.replace(parsed, replacement) == CredentialStatus.ok);

    assert(store.acquire(parsed, (scope const(ubyte)[] bytes) @safe
    {
        assert(bytes == cast(const(ubyte)[]) "contract:second");
        ++visits;
    }) == CredentialStatus.ok);
    assert(visits == 2);

    assert(store.remove(parsed) == CredentialStatus.ok);

    bool calledAfterRemove;
    assert(store.acquire(parsed, (scope const(ubyte)[]) @safe
    {
        calledAfterRemove = true;
    }) == CredentialStatus.notFound);
    assert(!calledAfterRemove);

    assert(store.replace(parsed, replacement) == CredentialStatus.notFound);
    assert(store.remove(parsed) == CredentialStatus.notFound);
}

void main()
{
    runStoreContract(new MemoryCredentialStore);
    runStoreContract(new MockCredentialStore);

    auto mock = new MockCredentialStore;
    auto secret = new SecretBuffer(cast(const(ubyte)[]) "locked-test");

    CredentialHandle handle;
    assert(mock.store(secret, handle) == CredentialStatus.ok);

    mock.forcedAcquireStatus = CredentialStatus.locked;

    bool called;
    assert(mock.acquire(handle, (scope const(ubyte)[]) @safe
    {
        called = true;
    }) == CredentialStatus.locked);
    assert(!called);
}
