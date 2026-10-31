/**
 * Core consumer API for credentials-d.
 *
 * Start here for CredentialNamespace, CredentialHandle, SecretBuffer and the
 * common CredentialStore operations.
 *
 * Examples:
 * ---
 * auto ns = CredentialNamespace("org.example.application");
 * auto store = new MemoryCredentialStore(ns);
 *
 * auto secret = SecretBuffer(cast(const(ubyte)[]) "token");
 *
 * CredentialHandle handle;
 * if (store.save(secret, handle) == CredentialStatus.ok)
 * {
 *     store.withSecret(handle, (scope const(ubyte)[] bytes) @safe
 *     {
 *         // Use the credential here.
 *     });
 * }
 * ---
 */
module credentials;

public import credentials.handle : CredentialHandle;
public import credentials.memory_store : MemoryCredentialStore;
public import credentials.namespace : CredentialNamespace;
public import credentials.secret : SecretBuffer;
public import credentials.store :
    CredentialStatus,
    CredentialStore,
    SecretCallback,
    StoreBlocking,
    StoreCapabilities,
    StoreConcurrency,
    StoreMobility,
    StoreProtection,
    StoreUnlockModel;

/**
 * Basic credential-store flow using the ephemeral memory backend.
 */
@("public package example")
unittest
{
    auto ns = CredentialNamespace("org.example.credentials");

    auto store = new MemoryCredentialStore(ns);
    scope(exit) store.clearAll();

    auto secret = SecretBuffer(cast(const(ubyte)[]) "example-token");

    CredentialHandle handle;
    assert(store.save(secret, handle) == CredentialStatus.ok);

    bool acquired;
    assert(store.withSecret(handle, (scope const(ubyte)[] bytes) @safe
    {
        assert(bytes == cast(const(ubyte)[]) "example-token");
        acquired = true;
    }) == CredentialStatus.ok);
    assert(acquired);

    assert(store.remove(handle) == CredentialStatus.ok);
}
