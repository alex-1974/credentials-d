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
import credentials.macos : MacOSCredentialStore;
import std.stdio : writeln;
import std.process : environment;

private CredentialNamespace namespaceOf(string value)
{
    return CredentialNamespace(value);
}

void main()
{
    auto ns = namespaceOf("org.alex1974.credentials-integration");
    auto store = new MacOSCredentialStore(ns);

    const capabilities = store.capabilities;
    assert(capabilities.persistent);
    assert(capabilities.protection ==
        StoreProtection.operatingSystem);
    assert(capabilities.unlockModel == StoreUnlockModel.operatingSystem);
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
    const stored = store.save(first, handle);
    writeln("macOS DPK initial store status code: ", cast(int) stored);

    // A generic command-line executable is not a production-qualified DPK
    // host. Apple requires an app-like signing/provisioning context for the
    // restricted keychain entitlements. Hosted CI explicitly marks that
    // context below. Different toolchains may be rejected at different points
    // by Security.framework; all accepted outcomes must still be fail-closed.
    const hostedUnprovisioned =
        environment.get("CREDENTIALS_D_MACOS_UNPROVISIONED_CI", "") == "1";
    const requireFull =
        environment.get("CREDENTIALS_D_MACOS_REQUIRE_FULL", "") == "1";

    assert(!(hostedUnprovisioned && requireFull));

    if (hostedUnprovisioned &&
        (stored == CredentialStatus.permissionDenied ||
         stored == CredentialStatus.unavailable ||
         stored == CredentialStatus.invalidInput))
    {
        assert(!handle.valid);
        writeln(
            "macOS DPK qualification: fail-closed in explicitly unprovisioned CLI host"
        );
        return;
    }

    // Outside the explicitly marked hosted-CI context, errSecParam /
    // invalidInput is never accepted as an entitlement substitute.
    if (!requireFull &&
        (stored == CredentialStatus.permissionDenied ||
         stored == CredentialStatus.unavailable))
    {
        assert(!handle.valid);
        writeln("macOS DPK qualification: fail-closed without usable entitlement context");
        return;
    }

    if (requireFull)
        writeln("macOS DPK qualification: strict provisioned-host mode");

    // A suitably signed execution environment, and every strict production
    // qualification run, must get the complete integration below.
    assert(stored == CredentialStatus.ok);
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

    auto reopened = new MacOSCredentialStore(ns);
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

    auto otherNs = namespaceOf("org.alex1974.credentials-other");
    auto otherStore =
        new MacOSCredentialStore(otherNs);

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

    writeln("macOS DPK qualification: full native integration PASS");
}
