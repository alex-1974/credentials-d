/**
 * Public package root for credentials-d.
 */
module credentials;

public import credentials.handle : CredentialHandle;
public import credentials.memory_store : MemoryCredentialStore;
public import credentials.secret : SecretBuffer;
public import credentials.store :
    CredentialStatus,
    CredentialStore,
    SecretVisitor,
    StoreCapabilities,
    StoreConcurrency;

/**
 * Basic credential-store flow using the ephemeral memory backend.
 */
@("public package example")
unittest
{
    auto store = new MemoryCredentialStore;
    auto secret = new SecretBuffer(cast(const(ubyte)[]) "example-token");

    CredentialHandle handle;
    assert(store.store(secret, handle) == CredentialStatus.ok);

    bool acquired;
    assert(store.acquire(handle, (scope const(ubyte)[] bytes) @safe
    {
        assert(bytes == cast(const(ubyte)[]) "example-token");
        acquired = true;
    }) == CredentialStatus.ok);
    assert(acquired);

    assert(store.remove(handle) == CredentialStatus.ok);
}
