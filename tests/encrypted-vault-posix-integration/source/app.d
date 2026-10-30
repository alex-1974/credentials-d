module app;

version (linux):

import core.sys.posix.sys.stat :
    S_IRUSR,
    S_IRWXU,
    S_IWUSR,
    chmod;
import core.sys.posix.unistd :
    getpid,
    symlink;
import core.thread : Thread;
import credentials :
    CredentialHandle,
    CredentialNamespace,
    CredentialStatus,
    SecretBuffer;
import credentials.backend.vault :
    EncryptedVaultCredentialStore;
import std.conv : to;
import std.file :
    copy,
    exists,
    mkdir,
    rmdirRecurse,
    tempDir,
    write;
import std.path : buildPath;
import std.string : toStringz;

private CredentialNamespace nsOf(string text)
{
    CredentialNamespace ns;
    assert(CredentialNamespace.tryParse(text, ns));
    return ns;
}

private void makePrivateDirectory(string path)
{
    mkdir(path);
    assert(chmod(
        toStringz(path),
        cast(uint) S_IRWXU
    ) == 0);
}

private void makeOwnerOnly(string path)
{
    assert(chmod(
        toStringz(path),
        cast(uint)(S_IRUSR | S_IWUSR)
    ) == 0);
}

void main()
{
    const root = buildPath(
        tempDir(),
        "credentials-d-vault-posix-" ~ getpid().to!string
    );

    if (root.exists)
        rmdirRecurse(root);

    makePrivateDirectory(root);
    scope(exit)
    {
        if (root.exists)
            rmdirRecurse(root);
    }

    const vaultPath = buildPath(root, "primary.vault");
    auto ns = nsOf("org.example.posixvault");
    auto otherNs = nsOf("org.example.other");

    auto passphrase =
        SecretBuffer(cast(const(ubyte)[]) "correct test passphrase");
    auto wrongPassphrase =
        SecretBuffer(cast(const(ubyte)[]) "wrong test passphrase");

    EncryptedVaultCredentialStore store;
    assert(EncryptedVaultCredentialStore.createNew(
        vaultPath,
        ns,
        passphrase,
        store
    ) == CredentialStatus.ok);
    assert(store !is null);
    assert(!store.isLocked);

    ubyte[] binary = [0x41, 0x00, 0x42, 0xff, 0x43];
    auto secret = SecretBuffer(binary);

    CredentialHandle handle;
    assert(store.store(secret, handle) == CredentialStatus.ok);
    assert(handle.valid);

    bool acquired;
    assert(store.acquire(
        handle,
        (scope const(ubyte)[] bytes) @safe
        {
            assert(bytes == binary);
            acquired = true;
        }
    ) == CredentialStatus.ok);
    assert(acquired);

    // Explicit lock destroys the retained vault key.
    store.lock();
    assert(store.isLocked);

    bool calledWhileLocked;
    assert(store.acquire(
        handle,
        (scope const(ubyte)[]) @safe
        {
            calledWhileLocked = true;
        }
    ) == CredentialStatus.locked);
    assert(!calledWhileLocked);

    assert(store.unlock(wrongPassphrase) ==
        CredentialStatus.permissionDenied);
    assert(store.isLocked);

    assert(store.unlock(passphrase) == CredentialStatus.ok);
    assert(!store.isLocked);

    // Reopen through a new store object.
    EncryptedVaultCredentialStore reopened;
    assert(EncryptedVaultCredentialStore.openExisting(
        vaultPath,
        ns,
        reopened
    ) == CredentialStatus.ok);
    assert(reopened.isLocked);
    assert(reopened.unlock(passphrase) == CredentialStatus.ok);

    assert(reopened.acquire(
        handle,
        (scope const(ubyte)[] bytes) @safe
        {
            assert(bytes == binary);
        }
    ) == CredentialStatus.ok);

    auto replacement =
        SecretBuffer(cast(const(ubyte)[]) "replacement");
    assert(reopened.replace(
        handle,
        replacement
    ) == CredentialStatus.ok);

    assert(reopened.acquire(
        handle,
        (scope const(ubyte)[] bytes) @safe
        {
            assert(bytes ==
                cast(const(ubyte)[]) "replacement");
        }
    ) == CredentialStatus.ok);

    // Wrong namespace is rejected without password work.
    EncryptedVaultCredentialStore wrongNamespace;
    assert(EncryptedVaultCredentialStore.openExisting(
        vaultPath,
        otherNs,
        wrongNamespace
    ) == CredentialStatus.invalidInput);
    assert(wrongNamespace is null);

    // A vault handle is bound to the specific non-secret vault id.
    const secondPath = buildPath(root, "second.vault");
    EncryptedVaultCredentialStore second;
    assert(EncryptedVaultCredentialStore.createNew(
        secondPath,
        ns,
        passphrase,
        second
    ) == CredentialStatus.ok);

    assert(second.acquire(
        handle,
        (scope const(ubyte)[]) @safe {}
    ) == CredentialStatus.invalidInput);

    // Replacing the underlying file with another valid vault invalidates the
    // retained session instead of applying the old key to the new vault.
    copy(secondPath, vaultPath);
    makeOwnerOnly(vaultPath);

    bool calledAfterSwap;
    assert(reopened.acquire(
        handle,
        (scope const(ubyte)[]) @safe
        {
            calledAfterSwap = true;
        }
    ) == CredentialStatus.locked);
    assert(!calledAfterSwap);
    assert(reopened.isLocked);

    // Use second.vault for the remaining file-state tests.
    second.lock();

    // Too-open vault permissions fail closed.
    assert(chmod(
        toStringz(secondPath),
        cast(uint)(S_IRUSR | S_IWUSR | 0x20 | 0x04)
    ) == 0);

    EncryptedVaultCredentialStore insecureMode;
    assert(EncryptedVaultCredentialStore.openExisting(
        secondPath,
        ns,
        insecureMode
    ) == CredentialStatus.permissionDenied);
    assert(insecureMode is null);
    makeOwnerOnly(secondPath);

    // Final-component symlink is never followed.
    const target = buildPath(root, "target.bin");
    target.write("not a vault");
    makeOwnerOnly(target);

    const linkedVault = buildPath(root, "linked.vault");
    assert(symlink(
        toStringz(target),
        toStringz(linkedVault)
    ) == 0);

    EncryptedVaultCredentialStore linked;
    assert(EncryptedVaultCredentialStore.openExisting(
        linkedVault,
        ns,
        linked
    ) == CredentialStatus.permissionDenied);
    assert(linked is null);

    // A malicious/pre-existing lock symlink is also rejected.
    const blockedPath = buildPath(root, "blocked.vault");
    const blockedLock = blockedPath ~ ".lock";
    assert(symlink(
        toStringz(target),
        toStringz(blockedLock)
    ) == 0);

    EncryptedVaultCredentialStore blocked;
    assert(EncryptedVaultCredentialStore.createNew(
        blockedPath,
        ns,
        passphrase,
        blocked
    ) == CredentialStatus.permissionDenied);
    assert(blocked is null);

    // Oversized encrypted files are rejected before content allocation/parsing.
    const oversizedPath = buildPath(root, "oversized.vault");
    auto oversized = new ubyte[17 * 1024 * 1024];
    oversizedPath.write(oversized);
    makeOwnerOnly(oversizedPath);

    EncryptedVaultCredentialStore oversizedStore;
    assert(EncryptedVaultCredentialStore.openExisting(
        oversizedPath,
        ns,
        oversizedStore
    ) == CredentialStatus.corruptData);
    assert(oversizedStore is null);

    // Independently opened store instances must serialize through the stable
    // sidecar flock. Both writes must survive; otherwise this would expose a
    // lost-update race despite each instance being internally synchronized.
    const concurrentPath = buildPath(root, "concurrent.vault");

    EncryptedVaultCredentialStore concurrentSeed;
    assert(EncryptedVaultCredentialStore.createNew(
        concurrentPath,
        ns,
        passphrase,
        concurrentSeed
    ) == CredentialStatus.ok);
    concurrentSeed.lock();

    EncryptedVaultCredentialStore writerA;
    EncryptedVaultCredentialStore writerB;
    assert(EncryptedVaultCredentialStore.openExisting(
        concurrentPath,
        ns,
        writerA
    ) == CredentialStatus.ok);
    assert(EncryptedVaultCredentialStore.openExisting(
        concurrentPath,
        ns,
        writerB
    ) == CredentialStatus.ok);
    assert(writerA.unlock(passphrase) == CredentialStatus.ok);
    assert(writerB.unlock(passphrase) == CredentialStatus.ok);

    CredentialHandle concurrentHandleA;
    CredentialHandle concurrentHandleB;
    CredentialStatus concurrentStatusA = CredentialStatus.backendFailure;
    CredentialStatus concurrentStatusB = CredentialStatus.backendFailure;

    auto threadA = new Thread({
        auto threadSecret =
            SecretBuffer(cast(const(ubyte)[]) "concurrent-a");
        concurrentStatusA =
            writerA.store(threadSecret, concurrentHandleA);
    });

    auto threadB = new Thread({
        auto threadSecret =
            SecretBuffer(cast(const(ubyte)[]) "concurrent-b");
        concurrentStatusB =
            writerB.store(threadSecret, concurrentHandleB);
    });

    threadA.start();
    threadB.start();
    threadA.join();
    threadB.join();

    assert(concurrentStatusA == CredentialStatus.ok);
    assert(concurrentStatusB == CredentialStatus.ok);
    assert(concurrentHandleA.valid);
    assert(concurrentHandleB.valid);

    writerA.lock();
    writerB.lock();

    EncryptedVaultCredentialStore concurrentCheck;
    assert(EncryptedVaultCredentialStore.openExisting(
        concurrentPath,
        ns,
        concurrentCheck
    ) == CredentialStatus.ok);
    assert(concurrentCheck.unlock(passphrase) == CredentialStatus.ok);

    assert(concurrentCheck.acquire(
        concurrentHandleA,
        (scope const(ubyte)[] bytes) @safe
        {
            assert(bytes == cast(const(ubyte)[]) "concurrent-a");
        }
    ) == CredentialStatus.ok);

    assert(concurrentCheck.acquire(
        concurrentHandleB,
        (scope const(ubyte)[] bytes) @safe
        {
            assert(bytes == cast(const(ubyte)[]) "concurrent-b");
        }
    ) == CredentialStatus.ok);

    // A crash before atomic commit can leave an encrypted same-directory
    // temporary image. Such residue must never shadow or replace the committed
    // vault. Copying the committed image models encrypted temp-file contents
    // without ever creating a plaintext fixture.
    const residuePath =
        concurrentPath ~ ".tmp-00000000000000000000000000000000";
    copy(concurrentPath, residuePath);
    makeOwnerOnly(residuePath);

    EncryptedVaultCredentialStore residueCheck;
    assert(EncryptedVaultCredentialStore.openExisting(
        concurrentPath,
        ns,
        residueCheck
    ) == CredentialStatus.ok);
    assert(residueCheck.unlock(passphrase) == CredentialStatus.ok);

    assert(residueCheck.acquire(
        concurrentHandleA,
        (scope const(ubyte)[] bytes) @safe
        {
            assert(bytes == cast(const(ubyte)[]) "concurrent-a");
        }
    ) == CredentialStatus.ok);

    concurrentCheck.lock();
    residueCheck.lock();

    // Logical delete survives reopen.
    EncryptedVaultCredentialStore finalStore;
    assert(EncryptedVaultCredentialStore.openExisting(
        secondPath,
        ns,
        finalStore
    ) == CredentialStatus.ok);
    assert(finalStore.unlock(passphrase) == CredentialStatus.ok);

    auto finalSecret =
        SecretBuffer(cast(const(ubyte)[]) "delete-me");
    CredentialHandle finalHandle;
    assert(finalStore.store(
        finalSecret,
        finalHandle
    ) == CredentialStatus.ok);

    assert(finalStore.remove(finalHandle) ==
        CredentialStatus.ok);

    bool calledAfterDelete;
    assert(finalStore.acquire(
        finalHandle,
        (scope const(ubyte)[]) @safe
        {
            calledAfterDelete = true;
        }
    ) == CredentialStatus.notFound);
    assert(!calledAfterDelete);

    finalStore.lock();
}
