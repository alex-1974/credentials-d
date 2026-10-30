/**
 * Windows Credential Manager backend.
 */
module credentials.backend.windows.store;

version (Windows):

pragma(lib, "Advapi32");

import core.volatile : volatileStore;
import core.sys.windows.windef :
    BOOL,
    DWORD,
    LPBYTE,
    LPWSTR;
import core.sys.windows.winbase :
    FILETIME,
    GetLastError;
import core.sys.windows.winerror :
    ERROR_ACCESS_DENIED,
    ERROR_INVALID_FLAGS,
    ERROR_INVALID_PARAMETER,
    ERROR_NOT_FOUND,
    ERROR_NO_SUCH_LOGON_SESSION;
import credentials.handle : CredentialHandle;
import credentials.namespace : CredentialNamespace;
import credentials.random : generateSecureLocator;
import credentials.secret : SecretBuffer;
import credentials.store :
    CredentialStatus,
    CredentialStore,
    SecretVisitor,
    StoreBlocking,
    StoreCapabilities,
    StoreConcurrency,
    StoreMobility,
    StoreProtection,
    StoreUnlockModel;
import std.utf : toUTF16z;

private enum DWORD CRED_TYPE_GENERIC = 1;
private enum DWORD CRED_PERSIST_NONE = 0;
private enum DWORD CRED_PERSIST_LOCAL_MACHINE = 2;
private enum DWORD CRED_TYPE_MAXIMUM = 7;
private enum size_t CRED_MAX_CREDENTIAL_BLOB_SIZE = 5 * 512;

private struct CREDENTIALW
{
    DWORD Flags;
    DWORD Type;
    LPWSTR TargetName;
    LPWSTR Comment;
    FILETIME LastWritten;
    DWORD CredentialBlobSize;
    LPBYTE CredentialBlob;
    DWORD Persist;
    DWORD AttributeCount;
    void* Attributes;
    LPWSTR TargetAlias;
    LPWSTR UserName;
}

private extern(Windows) @nogc nothrow
{
    BOOL CredWriteW(scope const CREDENTIALW* credential, DWORD flags);
    BOOL CredReadW(
        scope const(wchar)* targetName,
        DWORD type,
        DWORD flags,
        scope CREDENTIALW** credential
    );
    BOOL CredDeleteW(
        scope const(wchar)* targetName,
        DWORD type,
        DWORD flags
    );
    void CredFree(void* buffer);
    BOOL CredGetSessionTypes(scope DWORD* maximumPersist);
}

/**
 * Persistent credential store backed by the current Windows user's
 * Credential Manager.
 *
 * Generic credentials are stored with `CRED_PERSIST_LOCAL_MACHINE`: they are
 * available to subsequent logon sessions of the same user on this computer,
 * but this backend does not request enterprise/roaming persistence.
 *
 * Operations are serialized per store instance. No stronger cross-process
 * transaction guarantee is claimed.
 */
final class WindowsCredentialStore : CredentialStore
{
    private CredentialNamespace namespace_;
    private string handlePrefix_;
    private bool localPersistenceAvailable_;

    /**
     * Bind the backend to one application namespace.
     */
    this(CredentialNamespace credentialNamespace) @safe
    in (credentialNamespace.valid)
    {
        namespace_ = credentialNamespace;
        handlePrefix_ =
            "cred1:" ~ namespace_.serialize() ~ ":wincred:";

        localPersistenceAvailable_ = queryLocalPersistence();
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
            StoreProtection.nativeUserCredentialStore,
            StoreUnlockModel.osManaged,
            false,
            StoreMobility.localDevice,
            true,
            StoreBlocking.mayBlock,
            StoreConcurrency.serialized
        );
    }

    override CredentialStatus store(
        scope ref const SecretBuffer secret,
        out CredentialHandle handle
    ) @safe
    {
        synchronized (this)
        {
            return storeImpl(secret, handle);
        }
    }

    override CredentialStatus acquire(
        CredentialHandle handle,
        scope SecretVisitor visitor
    ) @safe
    {
        synchronized (this)
        {
            return acquireImpl(handle, visitor);
        }
    }

    override CredentialStatus replace(
        CredentialHandle handle,
        scope ref const SecretBuffer replacement
    ) @safe
    {
        synchronized (this)
        {
            return replaceImpl(handle, replacement);
        }
    }

    override CredentialStatus remove(CredentialHandle handle) @safe
    {
        synchronized (this)
        {
            return removeImpl(handle);
        }
    }

    private CredentialStatus storeImpl(
        scope ref const SecretBuffer secret,
        out CredentialHandle handle
    ) @trusted
    {
        handle = CredentialHandle.init;

        if (!localPersistenceAvailable_)
            return CredentialStatus.unavailable;

        if (secret.length > CRED_MAX_CREDENTIAL_BLOB_SIZE)
            return CredentialStatus.tooLarge;

        // CredWrite has update semantics and no atomic create-only mode.
        // Avoid an accidental overwrite by checking each cryptographically
        // random target before writing. A cross-process collision between this
        // check and the write remains bounded by the 128-bit locator space.
        foreach (_; 0 .. 4)
        {
            string locator;
            if (!generateSecureLocator(locator))
                return CredentialStatus.backendFailure;

            const serialized = handlePrefix_ ~ locator;
            const existsStatus = probe(serialized);

            if (existsStatus == CredentialStatus.ok)
                continue;

            if (existsStatus != CredentialStatus.notFound)
                return existsStatus;

            const writeStatus = write(serialized, secret);

            if (writeStatus == CredentialStatus.ok)
            {
                handle = CredentialHandle.trusted(serialized);
                return CredentialStatus.ok;
            }

            return writeStatus;
        }

        return CredentialStatus.backendFailure;
    }

    private CredentialStatus acquireImpl(
        CredentialHandle handle,
        scope SecretVisitor visitor
    ) @trusted
    {
        if (!validHandle(handle) || visitor is null)
            return CredentialStatus.invalidInput;

        auto target = nativeTarget(handle.serialize());
        CREDENTIALW* credential;

        if (!CredReadW(target.ptr, CRED_TYPE_GENERIC, 0, &credential))
            return mapReadDeleteError(GetLastError());

        if (credential is null)
            return CredentialStatus.backendFailure;

        scope(exit)
        {
            wipeCredentialBlob(credential);
            CredFree(credential);
        }

        if (credential.CredentialBlobSize >
            CRED_MAX_CREDENTIAL_BLOB_SIZE)
            return CredentialStatus.corruptData;

        if (credential.CredentialBlobSize != 0 &&
            credential.CredentialBlob is null)
            return CredentialStatus.corruptData;

        const(ubyte)[] bytes;
        if (credential.CredentialBlobSize != 0)
        {
            bytes = credential.CredentialBlob[
                0 .. credential.CredentialBlobSize
            ];
        }

        visitor(bytes);
        return CredentialStatus.ok;
    }

    private CredentialStatus replaceImpl(
        CredentialHandle handle,
        scope ref const SecretBuffer replacement
    ) @trusted
    {
        if (!validHandle(handle))
            return CredentialStatus.invalidInput;

        if (!localPersistenceAvailable_)
            return CredentialStatus.unavailable;

        if (replacement.length > CRED_MAX_CREDENTIAL_BLOB_SIZE)
            return CredentialStatus.tooLarge;

        // Prevent CredWrite's update-or-create semantics from turning replace
        // into an accidental create.
        const existing = probe(handle.serialize());
        if (existing != CredentialStatus.ok)
            return existing;

        return write(handle.serialize(), replacement);
    }

    private CredentialStatus removeImpl(CredentialHandle handle) @trusted
    {
        if (!validHandle(handle))
            return CredentialStatus.invalidInput;

        auto target = nativeTarget(handle.serialize());

        if (CredDeleteW(target.ptr, CRED_TYPE_GENERIC, 0))
            return CredentialStatus.ok;

        return mapReadDeleteError(GetLastError());
    }

    private CredentialStatus write(
        string serializedHandle,
        scope ref const SecretBuffer secret
    ) @trusted
    {
        auto target = nativeTarget(serializedHandle);

        CredentialStatus result = CredentialStatus.backendFailure;

        secret.withBytes((scope const(ubyte)[] bytes) @safe
        {
            CREDENTIALW credential;
            credential.Type = CRED_TYPE_GENERIC;
            credential.TargetName = cast(LPWSTR) target.ptr;
            credential.CredentialBlobSize = cast(DWORD) bytes.length;
            credential.CredentialBlob =
                cast(LPBYTE) bytes.ptr;
            credential.Persist = CRED_PERSIST_LOCAL_MACHINE;

            if (CredWriteW(&credential, 0))
            {
                result = CredentialStatus.ok;
            }
            else
            {
                result = mapWriteError(GetLastError());
            }
        });

        return result;
    }

    /**
     * Determine whether a serialized record currently exists.
     *
     * CredRead returns the secret as part of the allocated record. The blob is
     * wiped before CredFree even though this probe never exposes it.
     */
    private CredentialStatus probe(string serializedHandle) @trusted
    {
        auto target = nativeTarget(serializedHandle);
        CREDENTIALW* credential;

        if (!CredReadW(target.ptr, CRED_TYPE_GENERIC, 0, &credential))
            return mapReadDeleteError(GetLastError());

        if (credential is null)
            return CredentialStatus.backendFailure;

        wipeCredentialBlob(credential);
        CredFree(credential);
        return CredentialStatus.ok;
    }

    private bool validHandle(CredentialHandle handle) const
        @nogc nothrow @safe
    {
        return handle.valid && handle.hasStorePrefix(handlePrefix_);
    }

    private static const(wchar)[] nativeTarget(string serializedHandle)
        @safe
    {
        // TargetName is non-secret. Keep the backend prefix stable and avoid
        // user/profile names or OAuth metadata.
        return toUTF16z("credentials-d:" ~ serializedHandle);
    }

    private static bool queryLocalPersistence() @trusted
    {
        DWORD[CRED_TYPE_MAXIMUM] maximumPersist;

        if (!CredGetSessionTypes(maximumPersist.ptr))
            return false;

        return maximumPersist[CRED_TYPE_GENERIC] >=
            CRED_PERSIST_LOCAL_MACHINE;
    }

    private static CredentialStatus mapReadDeleteError(DWORD error)
        @nogc nothrow @safe
    {
        switch (error)
        {
            case ERROR_NOT_FOUND:
                return CredentialStatus.notFound;

            case ERROR_NO_SUCH_LOGON_SESSION:
                return CredentialStatus.unavailable;

            case ERROR_ACCESS_DENIED:
                return CredentialStatus.permissionDenied;

            case ERROR_INVALID_FLAGS:
            case ERROR_INVALID_PARAMETER:
                return CredentialStatus.backendFailure;

            default:
                return CredentialStatus.backendFailure;
        }
    }

    private static CredentialStatus mapWriteError(DWORD error)
        @nogc nothrow @safe
    {
        switch (error)
        {
            case ERROR_NO_SUCH_LOGON_SESSION:
                return CredentialStatus.unavailable;

            case ERROR_ACCESS_DENIED:
                return CredentialStatus.permissionDenied;

            case ERROR_INVALID_FLAGS:
            case ERROR_INVALID_PARAMETER:
                return CredentialStatus.backendFailure;

            default:
                return CredentialStatus.backendFailure;
        }
    }

    private static void wipeCredentialBlob(CREDENTIALW* credential)
        nothrow @nogc @trusted
    {
        if (credential is null ||
            credential.CredentialBlob is null)
            return;

        foreach (i; 0 .. credential.CredentialBlobSize)
        {
            volatileStore(
                credential.CredentialBlob + i,
                cast(ubyte) 0
            );
        }
    }
}
