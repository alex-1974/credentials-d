module app;

import credentials :
    CredentialHandle,
    CredentialNamespace,
    CredentialStatus,
    MemoryCredentialStore,
    SecretBuffer;

void main()
{
    auto store = new MemoryCredentialStore(
        CredentialNamespace("org.example.credentials")
    );
    scope(exit) store.clearAll();

    auto token = SecretBuffer(
        cast(const(ubyte)[]) "example-token"
    );

    CredentialHandle handle;
    assert(store.save(token, handle) == CredentialStatus.ok);

    // Persist this opaque, non-secret value in normal application settings.
    const savedHandle = handle.serialize();

    CredentialHandle restored;
    assert(CredentialHandle.tryParse(savedHandle, restored));

    assert(store.withSecret(
        restored,
        (scope const(ubyte)[] bytes) @safe
        {
            // Use the credential only where it is needed.
            assert(bytes == cast(const(ubyte)[]) "example-token");
        }
    ) == CredentialStatus.ok);

    auto replacement = SecretBuffer(
        cast(const(ubyte)[]) "updated-token"
    );
    assert(store.update(restored, replacement) == CredentialStatus.ok);

    assert(store.remove(restored) == CredentialStatus.ok);
}
