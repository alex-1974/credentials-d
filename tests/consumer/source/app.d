module app;

import credentials :
    CredentialHandle,
    CredentialStatus,
    MemoryCredentialStore,
    SecretBuffer;

void main()
{
    auto store = new MemoryCredentialStore;
    auto secret = new SecretBuffer(cast(const(ubyte)[]) "consumer-token");

    CredentialHandle handle;
    assert(store.store(secret, handle) == CredentialStatus.ok);

    bool acquired;
    assert(store.acquire(handle, (scope const(ubyte)[] bytes) @safe
    {
        assert(bytes == cast(const(ubyte)[]) "consumer-token");
        acquired = true;
    }) == CredentialStatus.ok);
    assert(acquired);

    const persisted = handle.serialize();

    CredentialHandle restored;
    assert(CredentialHandle.tryParse(persisted, restored));
    assert(restored.serialize() == persisted);

    assert(store.remove(restored) == CredentialStatus.ok);
}
