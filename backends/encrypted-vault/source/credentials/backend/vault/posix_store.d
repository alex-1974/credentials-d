/**
 * Encrypted credential vault implementation.
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
 * CredentialStore backed by one encrypted vault file.
 *
 * Choose this when users need a portable credential file or when the
 * application must manage its own vault instead of using the operating-system
 * credential store.
 *
 * New vaults are returned unlocked. Existing vaults open locked and must be
 * unlocked before save(), withSecret(), update() or remove() can be used.
 *
 * Examples:
 * ---
 * auto ns = CredentialNamespace("org.example.application");
 * auto passphrase = SecretBuffer(passphraseBytes);
 *
 * EncryptedCredentialVault vault;
 *
 * if (EncryptedCredentialVault.openExisting(
 *     "credentials.vault",
 *     ns,
 *     vault
 * ) == CredentialStatus.ok)
 * {
 *     if (vault.unlock(passphrase) == CredentialStatus.ok)
 *     {
 *         // Use the normal CredentialStore API.
 *     }
 * }
 *
 * scope(exit) vault.lock();
 * ---
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
     * Create a new vault file.
     *
     * Use this when setting up a vault for the first time. An existing file at
     * path is not replaced. On success, result is ready for normal
     * CredentialStore operations.
     *
     * Params:
     *     path = File to create.
     *     ns = Application credential namespace.
     *     passphrase = Passphrase chosen for this vault.
     *     result = Receives the unlocked vault.
     *
     * Returns:
     *     ok on success or a status describing why creation failed.
     *
     * Examples:
     * ---
     * EncryptedCredentialVault vault;
     *
     * auto status = EncryptedCredentialVault.createNew(
     *     "credentials.vault",
     *     ns,
     *     passphrase,
     *     vault
     * );
     * ---
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
     * Open an existing vault.
     *
     * The returned vault is locked. Call unlock() or unlockWithSecurityKey()
     * before using its stored credentials.
     *
     * Params:
     *     path = Existing vault file.
     *     ns = Application credential namespace used when the vault was made.
     *     result = Receives the locked vault.
     *
     * Returns:
     *     ok on success or a status describing why the vault could not be
     *     opened.
     *
     * Examples:
     * ---
     * EncryptedCredentialVault vault;
     *
     * if (EncryptedCredentialVault.openExisting(
     *     "credentials.vault",
     *     ns,
     *     vault
     * ) == CredentialStatus.ok)
     * {
     *     // Choose a configured unlock method.
     * }
     * ---
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
     * Unlock this vault with its passphrase.
     *
     * After ok, the normal CredentialStore operations are available until
     * lock() is called.
     *
     * Params:
     *     passphrase = Passphrase for this vault.
     *
     * Returns:
     *     ok when the vault is unlocked.
     *
     * Examples:
     * ---
     * if (vault.unlock(passphrase) == CredentialStatus.ok)
     * {
     *     // save(), withSecret(), update() and remove() are available.
     * }
     * ---
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
     * Lock the vault now.
     *
     * Call this when the application no longer needs credential access.
     */
    void lock() @safe
    {
        synchronized (this)
        {
            invalidateSession();
        }
    }

    /**
     * Whether unlock() or unlockWithSecurityKey() is required before use.
     */
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
                return CredentialStatus.writeOutcomeUnknown;

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
                callback
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
                return CredentialStatus.writeOutcomeUnknown;

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
                return CredentialStatus.writeOutcomeUnknown;

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
                return CredentialStatus.storageFailure;
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
                return CredentialStatus.corruptedData;
            case VaultCoreStatus.invalidInput:
                return CredentialStatus.invalidInput;
            case VaultCoreStatus.backendFailure:
                return CredentialStatus.storageFailure;
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
                return CredentialStatus.writeOutcomeUnknown;
            case VaultFileStatus.ioFailure:
                return CredentialStatus.storageFailure;
        }
    }

    private static CredentialStatus mapFileForRead(
        VaultFileStatus status
    ) @nogc nothrow @safe
    {
        if (status == VaultFileStatus.tooLarge ||
            status == VaultFileStatus.unsafeState)
            return CredentialStatus.corruptedData;

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
