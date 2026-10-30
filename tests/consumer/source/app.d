module app;

import credentials :
    CredentialHandle,
    CredentialNamespace,
    CredentialStatus,
    MemoryCredentialStore,
    SecretBuffer;

void main()
{
    CredentialNamespace ns;
    assert(CredentialNamespace.tryParse("org.example.consumer", ns));

    auto store = new MemoryCredentialStore(ns);
    scope(exit) store.clearAll();

    auto secret = SecretBuffer(cast(const(ubyte)[]) "consumer-token");

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
