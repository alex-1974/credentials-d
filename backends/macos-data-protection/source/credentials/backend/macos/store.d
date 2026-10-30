/**
 * macOS Data Protection Keychain backend.
 */
module credentials.backend.macos.store;

version (OSX):

import credentials.backend.macos.ffi;
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
import std.string : toStringz;

/**
 * Persistent credential store backed by the macOS Data Protection Keychain.
 *
 * Every SecItem operation explicitly targets the Data Protection Keychain,
 * disables synchronization, and uses a ThisDeviceOnly accessibility class.
 *
 * This backend does not fall back to the legacy file-based keychain.
 * A consumer without the required signing/entitlement context receives a
 * permission/unavailable status from Security.framework.
 */
final class MacOSDataProtectionCredentialStore : CredentialStore
{
    private CredentialNamespace namespace_;
    private string handlePrefix_;

    this(CredentialNamespace credentialNamespace) @safe
    in (credentialNamespace.valid)
    {
        namespace_ = credentialNamespace;
        handlePrefix_ =
            "cred1:" ~ namespace_.serialize() ~ ":dpkeychain:";
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

        foreach (_; 0 .. 4)
        {
            string locator;
            if (!generateSecureLocator(locator))
                return CredentialStatus.backendFailure;

            CredentialStatus status = CredentialStatus.backendFailure;

            secret.withBytes((scope const(ubyte)[] bytes) @safe
            {
                status = addNative(locator, bytes);
            });

            if (status == CredentialStatus.ok)
            {
                handle = CredentialHandle.trusted(handlePrefix_ ~ locator);
                return CredentialStatus.ok;
            }

            if (status == CredentialStatus.ambiguous)
                continue;

            return status;
        }

        return CredentialStatus.backendFailure;
    }

    private CredentialStatus acquireImpl(
        CredentialHandle handle,
        scope SecretVisitor visitor
    ) @trusted
    {
        if (visitor is null)
            return CredentialStatus.invalidInput;

        string locator;
        if (!extractLocator(handle, locator))
            return CredentialStatus.invalidInput;

        auto query = buildBaseQuery(locator);
        if (query is null)
            return CredentialStatus.backendFailure;

        scope(exit) CFRelease(query);

        CFDictionarySetValue(
            query,
            kSecReturnData,
            kCFBooleanTrue
        );
        CFDictionarySetValue(
            query,
            kSecMatchLimit,
            kSecMatchLimitOne
        );

        CFTypeRef result;
        const status = SecItemCopyMatching(query, &result);
        if (status != errSecSuccess)
            return mapStatus(status);

        if (result is null)
            return CredentialStatus.corruptData;

        scope(exit) CFRelease(result);

        if (CFGetTypeID(result) != CFDataGetTypeID())
            return CredentialStatus.corruptData;

        const data = cast(CFDataRef) result;
        const length = CFDataGetLength(data);

        if (length < 0)
            return CredentialStatus.corruptData;

        const(ubyte)* ptr = CFDataGetBytePtr(data);

        if (length != 0 && ptr is null)
            return CredentialStatus.corruptData;

        const(ubyte)[] bytes;
        if (length != 0)
            bytes = ptr[0 .. cast(size_t) length];

        visitor(bytes);
        return CredentialStatus.ok;
    }

    private CredentialStatus replaceImpl(
        CredentialHandle handle,
        scope ref const SecretBuffer replacement
    ) @trusted
    {
        string locator;
        if (!extractLocator(handle, locator))
            return CredentialStatus.invalidInput;

        auto query = buildBaseQuery(locator);
        if (query is null)
            return CredentialStatus.backendFailure;

        scope(exit) CFRelease(query);

        CredentialStatus status = CredentialStatus.backendFailure;

        replacement.withBytes((scope const(ubyte)[] bytes) @safe
        {
            status = updateNative(query, bytes);
        });

        return status;
    }

    private CredentialStatus removeImpl(CredentialHandle handle) @trusted
    {
        string locator;
        if (!extractLocator(handle, locator))
            return CredentialStatus.invalidInput;

        auto query = buildBaseQuery(locator);
        if (query is null)
            return CredentialStatus.backendFailure;

        scope(exit) CFRelease(query);

        return mapStatus(SecItemDelete(query));
    }

    /**
     * Add one generic-password item. Duplicate primary-key state maps to
     * ambiguous so store() can generate a fresh random locator.
     */
    private CredentialStatus addNative(
        string locator,
        scope const(ubyte)[] bytes
    ) @trusted
    {
        auto query = buildBaseQuery(locator);
        if (query is null)
            return CredentialStatus.backendFailure;

        scope(exit) CFRelease(query);

        CFDictionarySetValue(
            query,
            kSecAttrAccessible,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        );

        auto data = makeData(bytes);
        if (data is null)
            return CredentialStatus.backendFailure;

        scope(exit) CFRelease(data);

        CFDictionarySetValue(query, kSecValueData, data);

        return mapStatus(SecItemAdd(query, null));
    }

    private CredentialStatus updateNative(
        CFMutableDictionaryRef query,
        scope const(ubyte)[] bytes
    ) @trusted
    {
        auto updates = newDictionary();
        if (updates is null)
            return CredentialStatus.backendFailure;

        scope(exit) CFRelease(updates);

        auto data = makeData(bytes);
        if (data is null)
            return CredentialStatus.backendFailure;

        scope(exit) CFRelease(data);

        CFDictionarySetValue(updates, kSecValueData, data);

        return mapStatus(SecItemUpdate(query, updates));
    }

    /**
     * Every query explicitly selects:
     * - generic password;
     * - Data Protection Keychain;
     * - non-synchronizable items;
     * - this application namespace and opaque locator.
     */
    private CFMutableDictionaryRef buildBaseQuery(string locator) @trusted
    {
        auto query = newDictionary();
        if (query is null)
            return null;

        CFDictionarySetValue(
            query,
            kSecClass,
            kSecClassGenericPassword
        );
        CFDictionarySetValue(
            query,
            kSecUseDataProtectionKeychain,
            kCFBooleanTrue
        );
        CFDictionarySetValue(
            query,
            kSecAttrSynchronizable,
            kCFBooleanFalse
        );

        const serviceText =
            "credentials-d:" ~ namespace_.serialize();

        auto service = makeString(serviceText);
        auto account = makeString(locator);

        if (service is null || account is null)
        {
            if (service !is null)
                CFRelease(service);
            if (account !is null)
                CFRelease(account);
            CFRelease(query);
            return null;
        }

        CFDictionarySetValue(query, kSecAttrService, service);
        CFDictionarySetValue(query, kSecAttrAccount, account);

        CFRelease(service);
        CFRelease(account);

        return query;
    }

    private bool extractLocator(
        CredentialHandle handle,
        out string locator
    ) const @nogc nothrow @safe
    {
        locator = null;

        if (!handle.valid || !handle.hasStorePrefix(handlePrefix_))
            return false;

        const serialized = handle.serialize();
        if (serialized.length != handlePrefix_.length + 32)
            return false;

        const candidate = serialized[handlePrefix_.length .. $];

        foreach (char c; candidate)
        {
            if (!(
                (c >= '0' && c <= '9') ||
                (c >= 'a' && c <= 'f')
            ))
                return false;
        }

        locator = candidate;
        return true;
    }

    private static CFMutableDictionaryRef newDictionary() @trusted
    {
        return CFDictionaryCreateMutable(
            null,
            0,
            &kCFTypeDictionaryKeyCallBacks,
            &kCFTypeDictionaryValueCallBacks
        );
    }

    private static CFStringRef makeString(string value) @trusted
    {
        return CFStringCreateWithCString(
            null,
            toStringz(value),
            kCFStringEncodingUTF8
        );
    }

    /**
     * Create a short-lived CoreFoundation-owned immutable input buffer.
     *
     * This intentionally prefers explicit ownership over the zero-copy
     * constructor. Apple does not guarantee that
     * CFDataCreateWithBytesNoCopy avoids copying, and the external-buffer
     * lifetime proved fragile under the macOS LDC qualification path.
     *
     * The CFData is released immediately after the synchronous SecItem call.
     */
    private static CFDataRef makeData(
        scope const(ubyte)[] bytes
    ) @trusted
    {
        const(ubyte)* ptr = bytes.length == 0
            ? cast(const(ubyte)*) "".ptr
            : bytes.ptr;

        return CFDataCreate(
            null,
            ptr,
            cast(CFIndex) bytes.length
        );
    }

    private static CredentialStatus mapStatus(OSStatus status)
        @nogc nothrow @safe
    {
        switch (status)
        {
            case errSecSuccess:
                return CredentialStatus.ok;

            case errSecItemNotFound:
                return CredentialStatus.notFound;

            case errSecDuplicateItem:
                return CredentialStatus.ambiguous;

            case errSecInteractionNotAllowed:
            case errSecDataNotAvailable:
                return CredentialStatus.locked;

            case errSecInteractionRequired:
                return CredentialStatus.interactionRequired;

            case errSecUserCanceled:
                return CredentialStatus.userCancelled;

            case errSecMissingEntitlement:
            case errSecRestrictedAPI:
            case errSecAuthFailed:
            case errSecReadOnly:
                return CredentialStatus.permissionDenied;

            case errSecNotAvailable:
                return CredentialStatus.unavailable;

            case errSecDataTooLarge:
                return CredentialStatus.tooLarge;

            case errSecDecode:
                return CredentialStatus.corruptData;

            case errSecParam:
                return CredentialStatus.invalidInput;

            default:
                return CredentialStatus.backendFailure;
        }
    }
}
