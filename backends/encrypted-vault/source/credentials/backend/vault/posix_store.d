/**
 * Persistent POSIX encrypted-vault CredentialStore.
 */
module credentials.backend.vault.posix_store;

version (linux):

import credentials.backend.vault.core :
    VaultCoreStatus,
    createEmptyVaultImage,
    unlockVaultSession,
    unlockVaultSessionWithKey,
    validateVaultImageHeader,
    vaultIdFromImage,
    vaultAcquireUnlocked,
    vaultPutUnlocked,
    vaultRemoveUnlocked,
    vaultReplaceUnlocked;
import credentials.backend.vault.posix_file :
    VaultFileLock,
    VaultFileStatus,
    acquireVaultFileLock,
    createVaultImage,
    readVaultImage,
    replaceVaultImage;
import credentials.backend.vault.session : VaultSession;
import credentials.backend.vault.sodium : vaultKeyBytes;
import credentials.handle : CredentialHandle;
import credentials.namespace : CredentialNamespace;
import credentials.secret : SecretBuffer;
import credentials.store :
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
 * Application-controlled encrypted credential vault on a hardened POSIX file.
 *
 * Native OS credential stores remain the normal default for applications.
 * This backend is selected explicitly when an application-controlled vault is
 * required.
 *
 * The store is bound to one path and one CredentialNamespace. Existing vaults
 * open in the locked state. unlock() retains only the random vault key; the
 * passphrase is not retained.
 *
 * Explicit lock() is part of the security contract. The destructor performs a
 * best-effort lock, but D GC finalization timing is not a prompt-destruction
 * guarantee.
 */
final class EncryptedCredentialVault : CredentialStore
{
    private string path_;
    private CredentialNamespace namespace_;
    private VaultSession session_;
    private string handlePrefix_;

    private this(string path, CredentialNamespace ns) @safe
    {
        path_ = path;
        namespace_ = ns;
        session_ = new VaultSession;
    }

    /**
     * Create a new vault without replacing an existing final path.
     *
     * On success, result is returned unlocked.
     */
    static CredentialStatus createNew(
        string path,
        CredentialNamespace ns,
        scope ref const SecretBuffer passphrase,
        out EncryptedCredentialVault result
    ) @safe
    {
        result = null;

        if (!validPath(path) || !ns.valid || passphrase.empty)
            return CredentialStatus.invalidInput;

        ubyte[] image;
        auto coreStatus =
            createEmptyVaultImage(ns, passphrase, image);
        if (coreStatus != VaultCoreStatus.ok)
            return mapCore(coreStatus);

        VaultFileLock fileLock;
        auto fileStatus =
            acquireVaultFileLock(path, fileLock);
        if (fileStatus != VaultFileStatus.ok)
            return mapFileForAccess(fileStatus);

        fileStatus = createVaultImage(path, image);
        if (fileStatus != VaultFileStatus.ok)
            return mapCreateFile(fileStatus);

        auto candidate =
            new EncryptedCredentialVault(path, ns);

        coreStatus = unlockVaultSession(
            image,
            ns,
            passphrase,
            candidate.session_
        );
        if (coreStatus != VaultCoreStatus.ok)
            return mapCore(coreStatus);

        candidate.refreshHandlePrefix();
        result = candidate;
        return CredentialStatus.ok;
    }

    /**
     * Open and structurally validate an existing vault in the locked state.
     *
     * No password KDF or plaintext decryption occurs here.
     */
    static CredentialStatus openExisting(
        string path,
        CredentialNamespace ns,
        out EncryptedCredentialVault result
    ) @safe
    {
        result = null;

        if (!validPath(path) || !ns.valid)
            return CredentialStatus.invalidInput;

        VaultFileLock fileLock;
        auto fileStatus =
            acquireVaultFileLock(path, fileLock);
        if (fileStatus != VaultFileStatus.ok)
            return mapFileForAccess(fileStatus);

        ubyte[] image;
        fileStatus = readVaultImage(path, image);
        if (fileStatus != VaultFileStatus.ok)
            return mapFileForRead(fileStatus);

        const coreStatus =
            validateVaultImageHeader(image, ns);
        if (coreStatus != VaultCoreStatus.ok)
            return mapCore(coreStatus);

        result = new EncryptedCredentialVault(path, ns);
        return CredentialStatus.ok;
    }

    /**
     * Unlock with a passphrase.
     *
     * Successful unlock retains only the random vault key.
     */
    CredentialStatus unlock(
        scope ref const SecretBuffer passphrase
    ) @safe
    {
        synchronized (this)
        {
            if (session_.unlocked)
                return CredentialStatus.ok;

            VaultFileLock fileLock;
            auto fileStatus =
                acquireVaultFileLock(path_, fileLock);
            if (fileStatus != VaultFileStatus.ok)
                return mapFileForAccess(fileStatus);

            ubyte[] image;
            fileStatus = readVaultImage(path_, image);
            if (fileStatus != VaultFileStatus.ok)
                return mapFileForRead(fileStatus);

            const coreStatus = unlockVaultSession(
                image,
                namespace_,
                passphrase,
                session_
            );

            if (coreStatus != VaultCoreStatus.ok)
            {
                invalidateSession();
                return mapCore(coreStatus);
            }

            refreshHandlePrefix();
            return CredentialStatus.ok;
        }
    }

    /**
     * Clear the retained vault key.
     */
    void lock() @safe
    {
        synchronized (this)
        {
            invalidateSession();
        }
    }

    @property bool isLocked() const @safe
    {
        synchronized (this)
        {
            return !session_.unlocked;
        }
    }

    override @property CredentialNamespace credentialNamespace() const
        @nogc nothrow @safe
    {
        return namespace_;
    }

    override @property StoreCapabilities capabilities() const
        @nogc nothrow @safe
    {
        return StoreCapabilities(
            true,
            StoreProtection.encryptedVault,
            StoreUnlockModel.application,
            false,
            StoreMobility.portableFile,
            true,
            StoreBlocking.mayBlock,
            StoreConcurrency.serialized
        );
    }

    override CredentialStatus save(
        scope ref const SecretBuffer secret,
        out CredentialHandle handle
    ) @safe
    {
        synchronized (this)
        {
            handle = CredentialHandle.init;

            if (!session_.unlocked)
                return CredentialStatus.locked;

            VaultFileLock fileLock;
            auto fileStatus =
                acquireVaultFileLock(path_, fileLock);
            if (fileStatus != VaultFileStatus.ok)
                return mapFileForAccess(fileStatus);

            ubyte[] image;
            fileStatus = readVaultImage(path_, image);
            if (fileStatus != VaultFileStatus.ok)
                return mapFileForRead(fileStatus);

            string locator;
            const coreStatus = vaultPutUnlocked(
                image,
                namespace_,
                session_,
                secret,
                locator
            );

            if (coreStatus != VaultCoreStatus.ok)
                return handleCoreFailure(coreStatus);

            const serialized = handlePrefix_ ~ locator;
            handle = CredentialHandle.trusted(serialized);

            fileStatus = replaceVaultImage(path_, image);

            if (fileStatus == VaultFileStatus.commitUncertain)
                return CredentialStatus.commitUncertain;

            if (fileStatus != VaultFileStatus.ok)
            {
                handle = CredentialHandle.init;
                return mapFileForAccess(fileStatus);
            }

            return CredentialStatus.ok;
        }
    }

    override CredentialStatus withSecret(
        CredentialHandle handle,
        scope SecretCallback callback
    ) @safe
    {
        synchronized (this)
        {
            if (!session_.unlocked)
                return CredentialStatus.locked;

            string locator;
            if (!locatorFromHandle(handle, locator) ||
                callback is null)
                return CredentialStatus.invalidInput;

            VaultFileLock fileLock;
            auto fileStatus =
                acquireVaultFileLock(path_, fileLock);
            if (fileStatus != VaultFileStatus.ok)
                return mapFileForAccess(fileStatus);

            ubyte[] image;
            fileStatus = readVaultImage(path_, image);
            if (fileStatus != VaultFileStatus.ok)
                return mapFileForRead(fileStatus);

            const coreStatus = vaultAcquireUnlocked(
                image,
                namespace_,
                session_,
                locator,
                visitor
            );

            if (coreStatus != VaultCoreStatus.ok)
                return handleCoreFailure(coreStatus);

            return CredentialStatus.ok;
        }
    }

    override CredentialStatus update(
        CredentialHandle handle,
        scope ref const SecretBuffer replacement
    ) @safe
    {
        synchronized (this)
        {
            if (!session_.unlocked)
                return CredentialStatus.locked;

            string locator;
            if (!locatorFromHandle(handle, locator))
                return CredentialStatus.invalidInput;

            VaultFileLock fileLock;
            auto fileStatus =
                acquireVaultFileLock(path_, fileLock);
            if (fileStatus != VaultFileStatus.ok)
                return mapFileForAccess(fileStatus);

            ubyte[] image;
            fileStatus = readVaultImage(path_, image);
            if (fileStatus != VaultFileStatus.ok)
                return mapFileForRead(fileStatus);

            const coreStatus = vaultReplaceUnlocked(
                image,
                namespace_,
                session_,
                locator,
                replacement
            );

            if (coreStatus != VaultCoreStatus.ok)
                return handleCoreFailure(coreStatus);

            fileStatus = replaceVaultImage(path_, image);
            if (fileStatus == VaultFileStatus.commitUncertain)
                return CredentialStatus.commitUncertain;

            return mapFileForAccess(fileStatus);
        }
    }

    override CredentialStatus remove(CredentialHandle handle) @safe
    {
        synchronized (this)
        {
            if (!session_.unlocked)
                return CredentialStatus.locked;

            string locator;
            if (!locatorFromHandle(handle, locator))
                return CredentialStatus.invalidInput;

            VaultFileLock fileLock;
            auto fileStatus =
                acquireVaultFileLock(path_, fileLock);
            if (fileStatus != VaultFileStatus.ok)
                return mapFileForAccess(fileStatus);

            ubyte[] image;
            fileStatus = readVaultImage(path_, image);
            if (fileStatus != VaultFileStatus.ok)
                return mapFileForRead(fileStatus);

            const coreStatus = vaultRemoveUnlocked(
                image,
                namespace_,
                session_,
                locator
            );

            if (coreStatus != VaultCoreStatus.ok)
                return handleCoreFailure(coreStatus);

            fileStatus = replaceVaultImage(path_, image);
            if (fileStatus == VaultFileStatus.commitUncertain)
                return CredentialStatus.commitUncertain;

            return mapFileForAccess(fileStatus);
        }
    }

    /**
     * Copy the current authenticated vault id and retained vault key for
     * creation of an external unlock envelope.
     *
     * Package-private: callers outside the vault implementation never receive
     * raw vault-key bytes.
     */
    package(credentials.backend.vault) CredentialStatus copyUnlockMaterial(
        out ubyte[16] vaultId,
        out ubyte[vaultKeyBytes] vaultKey
    ) @safe
    {
        synchronized (this)
        {
            vaultId[] = 0;
            vaultKey[] = 0;

            if (!session_.unlocked)
                return CredentialStatus.locked;

            VaultFileLock fileLock;
            auto fileStatus =
                acquireVaultFileLock(path_, fileLock);
            if (fileStatus != VaultFileStatus.ok)
                return mapFileForAccess(fileStatus);

            ubyte[] image;
            fileStatus = readVaultImage(path_, image);
            if (fileStatus != VaultFileStatus.ok)
                return mapFileForRead(fileStatus);

            const coreStatus =
                vaultIdFromImage(image, namespace_, vaultId);
            if (coreStatus != VaultCoreStatus.ok)
                return handleCoreFailure(coreStatus);

            if (!session_.matchesVault(vaultId))
            {
                invalidateSession();
                vaultId[] = 0;
                return CredentialStatus.locked;
            }

            bool copied;
            session_.withKey((scope const(ubyte)[] key) @safe
            {
                if (key.length == vaultKey.length)
                {
                    vaultKey[] = key[];
                    copied = true;
                }
            });

            if (!copied)
            {
                vaultKey[] = 0;
                return CredentialStatus.backendFailure;
            }

            return CredentialStatus.ok;
        }
    }

    /**
     * Read the current non-secret vault id while remaining locked.
     */
    package(credentials.backend.vault) CredentialStatus currentVaultId(
        out ubyte[16] vaultId
    ) @safe
    {
        synchronized (this)
        {
            vaultId[] = 0;

            VaultFileLock fileLock;
            auto fileStatus =
                acquireVaultFileLock(path_, fileLock);
            if (fileStatus != VaultFileStatus.ok)
                return mapFileForAccess(fileStatus);

            ubyte[] image;
            fileStatus = readVaultImage(path_, image);
            if (fileStatus != VaultFileStatus.ok)
                return mapFileForRead(fileStatus);

            return mapCore(
                vaultIdFromImage(image, namespace_, vaultId)
            );
        }
    }

    /**
     * Unlock from a vault key recovered by an authenticated external
     * protector envelope.
     */
    package(credentials.backend.vault) CredentialStatus unlockWithVaultKey(
        scope const(ubyte)[] vaultKey
    ) @safe
    {
        synchronized (this)
        {
            if (session_.unlocked)
                return CredentialStatus.ok;

            if (vaultKey.length != vaultKeyBytes)
                return CredentialStatus.invalidInput;

            VaultFileLock fileLock;
            auto fileStatus =
                acquireVaultFileLock(path_, fileLock);
            if (fileStatus != VaultFileStatus.ok)
                return mapFileForAccess(fileStatus);

            ubyte[] image;
            fileStatus = readVaultImage(path_, image);
            if (fileStatus != VaultFileStatus.ok)
                return mapFileForRead(fileStatus);

            const coreStatus = unlockVaultSessionWithKey(
                image,
                namespace_,
                vaultKey,
                session_
            );

            if (coreStatus != VaultCoreStatus.ok)
            {
                invalidateSession();
                return mapCore(coreStatus);
            }

            refreshHandlePrefix();
            return CredentialStatus.ok;
        }
    }

    ~this() scope @safe
    {
        invalidateSession();
    }

    private void refreshHandlePrefix() @safe
    in (session_.unlocked)
    {
        handlePrefix_ =
            "cred1:" ~
            namespace_.serialize() ~
            ":vault:" ~
            session_.vaultIdText() ~
            ":";
    }

    private void invalidateSession() scope @safe
    {
        if (session_ !is null)
            session_.clear();
        handlePrefix_ = null;
    }

    private CredentialStatus handleCoreFailure(
        VaultCoreStatus status
    ) @safe
    {
        if (status == VaultCoreStatus.locked)
        {
            invalidateSession();
            return CredentialStatus.locked;
        }

        return mapCore(status);
    }

    private bool locatorFromHandle(
        CredentialHandle handle,
        out string locator
    ) const @safe
    {
        locator = null;

        if (handlePrefix_.length == 0 ||
            !handle.valid ||
            !handle.hasStorePrefix(handlePrefix_))
            return false;

        const serialized = handle.serialize();

        if (serialized.length != handlePrefix_.length + 32)
            return false;

        const tail = serialized[handlePrefix_.length .. $];

        foreach (char c; tail)
        {
            if (!(
                (c >= '0' && c <= '9') ||
                (c >= 'a' && c <= 'f')
            ))
                return false;
        }

        locator = tail;
        return true;
    }

    private static bool validPath(string path)
        @nogc nothrow @safe
    {
        if (path.length == 0)
            return false;

        foreach (char c; path)
            if (c == '\0')
                return false;

        return true;
    }

    private static CredentialStatus mapCore(
        VaultCoreStatus status
    ) @nogc nothrow @safe
    {
        final switch (status)
        {
            case VaultCoreStatus.ok:
                return CredentialStatus.ok;
            case VaultCoreStatus.notFound:
                return CredentialStatus.notFound;
            case VaultCoreStatus.locked:
                return CredentialStatus.locked;
            case VaultCoreStatus.unavailable:
                return CredentialStatus.unavailable;
            case VaultCoreStatus.permissionDenied:
                return CredentialStatus.permissionDenied;
            case VaultCoreStatus.tooLarge:
                return CredentialStatus.tooLarge;
            case VaultCoreStatus.corruptData:
                return CredentialStatus.corruptData;
            case VaultCoreStatus.invalidInput:
                return CredentialStatus.invalidInput;
            case VaultCoreStatus.backendFailure:
                return CredentialStatus.backendFailure;
        }
    }

    private static CredentialStatus mapFileForAccess(
        VaultFileStatus status
    ) @nogc nothrow @safe
    {
        final switch (status)
        {
            case VaultFileStatus.ok:
                return CredentialStatus.ok;
            case VaultFileStatus.notFound:
                return CredentialStatus.unavailable;
            case VaultFileStatus.alreadyExists:
                return CredentialStatus.invalidInput;
            case VaultFileStatus.permissionDenied:
            case VaultFileStatus.unsafeState:
                return CredentialStatus.permissionDenied;
            case VaultFileStatus.tooLarge:
                return CredentialStatus.tooLarge;
            case VaultFileStatus.commitUncertain:
                return CredentialStatus.commitUncertain;
            case VaultFileStatus.ioFailure:
                return CredentialStatus.backendFailure;
        }
    }

    private static CredentialStatus mapFileForRead(
        VaultFileStatus status
    ) @nogc nothrow @safe
    {
        if (status == VaultFileStatus.tooLarge ||
            status == VaultFileStatus.unsafeState)
            return CredentialStatus.corruptData;

        return mapFileForAccess(status);
    }

    private static CredentialStatus mapCreateFile(
        VaultFileStatus status
    ) @nogc nothrow @safe
    {
        if (status == VaultFileStatus.alreadyExists)
            return CredentialStatus.invalidInput;

        return mapFileForAccess(status);
    }
}
