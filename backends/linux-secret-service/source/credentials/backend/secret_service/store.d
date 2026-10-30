/**
 * Linux Secret Service backend using libsecret.
 */
module credentials.backend.secret_service.store;

version (linux):

import core.stdc.stddef : ptrdiff_t;
import credentials.backend.secret_service.ffi;
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

private enum schemaName = "org.alex1974.credentials";
private enum namespaceAttribute = "namespace";
private enum credentialAttribute = "credential";
private enum genericLabel = "credentials-d credential";
private enum binaryContentType = "application/octet-stream";

/**
 * Persistent Linux credential store backed by the Secret Service API.
 *
 * One independent libsecret service proxy and secure transfer session are
 * retained per store instance and operations are serialized. This avoids
 * opening a new D-Bus/OpenSession connection for every credential operation.
 *
 * Secret Service attributes are routing metadata and are not confidential.
 * This backend stores only the validated application namespace and an opaque
 * random credential locator as attributes.
 *
 * Synchronous libsecret operations can block indefinitely and may prompt.
 * Consumers must not invoke this backend on a GUI/render thread.
 */
final class LinuxSecretServiceStore : CredentialStore
{
    private CredentialNamespace namespace_;
    private string handlePrefix_;
    private SecretSchema* schema_;
    private SecretService* service_;
    private CredentialStatus initStatus_ = CredentialStatus.backendFailure;
    private bool closed_;

    /**
     * Bind this store to one application namespace and open one libsecret
     * service proxy with an established secret-transfer session.
     */
    this(CredentialNamespace credentialNamespace) @trusted
    in (credentialNamespace.valid)
    {
        namespace_ = credentialNamespace;
        handlePrefix_ =
            "cred1:" ~ namespace_.serialize() ~ ":secret-service:";

        schema_ = createSchema();
        if (schema_ is null)
        {
            initStatus_ = CredentialStatus.backendFailure;
            return;
        }

        GError* error;
        service_ = secret_service_open_sync(
            secret_service_get_type(),
            null,
            SECRET_SERVICE_OPEN_SESSION,
            null,
            &error
        );

        if (service_ is null)
        {
            initStatus_ = consumeError(
                error,
                CredentialStatus.unavailable
            );
            return;
        }

        if (error !is null)
            g_error_free(error);

        initStatus_ = CredentialStatus.ok;
    }

    /**
     * Release the retained native service and schema promptly.
     *
     * A later credential operation on a closed store fails with
     * `unavailable`.
     */
    void close() @trusted
    {
        synchronized (this)
        {
            if (closed_)
                return;

            closed_ = true;
            releaseNative();
        }
    }

    ~this() @trusted
    {
        releaseNative();
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
            // Secret Service does not promise that provider storage can never
            // roam/synchronize. Do not claim local-device-only protection.
            StoreMobility.mayRoam,
            true,
            StoreBlocking.mayPrompt,
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

    private CredentialStatus readyStatus() const
        @nogc nothrow @safe
    {
        if (closed_)
            return CredentialStatus.unavailable;

        return initStatus_;
    }

    private CredentialStatus storeImpl(
        scope ref const SecretBuffer secret,
        out CredentialHandle handle
    ) @trusted
    {
        handle = CredentialHandle.init;

        const ready = readyStatus();
        if (ready != CredentialStatus.ok)
            return ready;

        if (secret.length > cast(size_t) ptrdiff_t.max)
            return CredentialStatus.tooLarge;

        // secret_service_store_sync has update semantics for matching
        // attributes. Probe the cryptographically random locator first. The
        // remaining cross-process probe/store race is bounded by 128-bit
        // locator collision probability.
        foreach (_; 0 .. 4)
        {
            string locator;
            if (!generateSecureLocator(locator))
                return CredentialStatus.backendFailure;

            SecretItem* existing;
            const probeStatus = findExact(
                locator,
                SECRET_SEARCH_ALL,
                existing
            );

            if (probeStatus == CredentialStatus.ok)
            {
                g_object_unref(existing);
                continue;
            }

            if (probeStatus == CredentialStatus.ambiguous)
                return probeStatus;

            if (probeStatus != CredentialStatus.notFound)
                return probeStatus;

            const stored = storeValue(locator, secret);
            if (stored != CredentialStatus.ok)
                return stored;

            handle = CredentialHandle.trusted(handlePrefix_ ~ locator);
            return CredentialStatus.ok;
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

        const ready = readyStatus();
        if (ready != CredentialStatus.ok)
            return ready;

        SecretItem* item;
        auto status = findExact(
            locator,
            SECRET_SEARCH_ALL |
            SECRET_SEARCH_UNLOCK |
            SECRET_SEARCH_LOAD_SECRETS,
            item
        );
        if (status != CredentialStatus.ok)
            return status;

        scope(exit) g_object_unref(item);

        if (secret_item_get_locked(item))
            return CredentialStatus.locked;

        SecretValue* value = secret_item_get_secret(item);

        if (value is null)
        {
            GError* error;
            if (!secret_item_load_secret_sync(item, null, &error))
                return consumeError(
                    error,
                    CredentialStatus.backendFailure
                );

            if (error !is null)
                g_error_free(error);

            if (secret_item_get_locked(item))
                return CredentialStatus.locked;

            value = secret_item_get_secret(item);
            if (value is null)
                return CredentialStatus.corruptData;
        }

        scope(exit) secret_value_unref(value);

        gsize length;
        const(char)* data = secret_value_get(value, &length);

        if (length != 0 && data is null)
            return CredentialStatus.corruptData;

        const(ubyte)[] bytes;
        if (length != 0)
            bytes = cast(const(ubyte)[]) data[0 .. length];

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

        const ready = readyStatus();
        if (ready != CredentialStatus.ok)
            return ready;

        if (replacement.length > cast(size_t) ptrdiff_t.max)
            return CredentialStatus.tooLarge;

        SecretItem* item;
        auto status = findExact(
            locator,
            SECRET_SEARCH_ALL | SECRET_SEARCH_UNLOCK,
            item
        );
        if (status != CredentialStatus.ok)
            return status;

        scope(exit) g_object_unref(item);

        if (secret_item_get_locked(item))
            return CredentialStatus.locked;

        SecretValue* value = makeSecretValue(replacement);
        if (value is null)
            return CredentialStatus.backendFailure;

        scope(exit) secret_value_unref(value);

        GError* error;
        if (!secret_item_set_secret_sync(item, value, null, &error))
            return consumeError(
                error,
                CredentialStatus.backendFailure
            );

        if (error !is null)
            g_error_free(error);

        return CredentialStatus.ok;
    }

    private CredentialStatus removeImpl(CredentialHandle handle) @trusted
    {
        string locator;
        if (!extractLocator(handle, locator))
            return CredentialStatus.invalidInput;

        const ready = readyStatus();
        if (ready != CredentialStatus.ok)
            return ready;

        SecretItem* item;
        auto status = findExact(
            locator,
            SECRET_SEARCH_ALL | SECRET_SEARCH_UNLOCK,
            item
        );
        if (status != CredentialStatus.ok)
            return status;

        scope(exit) g_object_unref(item);

        if (secret_item_get_locked(item))
            return CredentialStatus.locked;

        GError* error;
        if (!secret_item_delete_sync(item, null, &error))
            return consumeError(
                error,
                CredentialStatus.backendFailure
            );

        if (error !is null)
            g_error_free(error);

        return CredentialStatus.ok;
    }

    private CredentialStatus storeValue(
        string locator,
        scope ref const SecretBuffer secret
    ) @trusted
    {
        GHashTable* attributes = buildAttributes(locator);
        if (attributes is null)
            return CredentialStatus.backendFailure;

        scope(exit) g_hash_table_unref(attributes);

        SecretValue* value = makeSecretValue(secret);
        if (value is null)
            return CredentialStatus.backendFailure;

        scope(exit) secret_value_unref(value);

        GError* error;
        const stored = secret_service_store_sync(
            service_,
            schema_,
            attributes,
            null,
            genericLabel.ptr,
            value,
            null,
            &error
        );

        if (!stored)
            return consumeError(
                error,
                CredentialStatus.backendFailure
            );

        if (error !is null)
            g_error_free(error);

        return CredentialStatus.ok;
    }

    /**
     * Find exactly one item by namespace + opaque locator.
     *
     * Search always requests ALL matches. Returning the first match when
     * multiple items exist would make corrupted/hostile metadata silently
     * choose a credential, so ambiguity fails closed.
     *
     * On success, `item` owns one GObject reference.
     */
    private CredentialStatus findExact(
        string locator,
        int flags,
        out SecretItem* item
    ) @trusted
    {
        item = null;

        GHashTable* attributes = buildAttributes(locator);
        if (attributes is null)
            return CredentialStatus.backendFailure;

        scope(exit) g_hash_table_unref(attributes);

        GError* error;
        GList* items = secret_service_search_sync(
            service_,
            schema_,
            attributes,
            flags | SECRET_SEARCH_ALL,
            null,
            &error
        );

        if (error !is null)
        {
            if (items !is null)
                freeItemList(items);

            return consumeError(
                error,
                CredentialStatus.backendFailure
            );
        }

        const count = items is null ? 0 : g_list_length(items);

        if (count == 0)
        {
            if (items !is null)
                freeItemList(items);

            return CredentialStatus.notFound;
        }

        if (count != 1)
        {
            freeItemList(items);
            return CredentialStatus.ambiguous;
        }

        auto raw = g_list_nth_data(items, 0);
        if (raw is null)
        {
            freeItemList(items);
            return CredentialStatus.corruptData;
        }

        item = cast(SecretItem*) g_object_ref(raw);
        freeItemList(items);

        return item is null
            ? CredentialStatus.backendFailure
            : CredentialStatus.ok;
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

    private GHashTable* buildAttributes(string locator) @trusted
    {
        auto attributes = g_hash_table_new_full(
            cast(void*) &g_str_hash,
            cast(void*) &g_str_equal,
            cast(void*) &g_free,
            cast(void*) &g_free
        );

        if (attributes is null)
            return null;

        insertOwned(
            attributes,
            namespaceAttribute,
            namespace_.serialize()
        );
        insertOwned(
            attributes,
            credentialAttribute,
            locator
        );

        return attributes;
    }

    private static void insertOwned(
        GHashTable* table,
        string key,
        string value
    ) @trusted
    {
        auto keyCopy = g_strdup(toStringz(key));
        auto valueCopy = g_strdup(toStringz(value));

        // GLib allocation APIs abort on allocation failure; at this point both
        // pointers are expected to be valid. The hash table owns them.
        g_hash_table_insert(table, keyCopy, valueCopy);
    }

    private static SecretSchema* createSchema() @trusted
    {
        auto types = g_hash_table_new_full(
            cast(void*) &g_str_hash,
            cast(void*) &g_str_equal,
            null,
            null
        );

        if (types is null)
            return null;

        scope(exit) g_hash_table_unref(types);

        // SecretSchemaAttributeType.STRING is value zero. NULL is therefore a
        // valid encoded hash-table value for the schema binding API.
        g_hash_table_insert(
            types,
            cast(void*) namespaceAttribute.ptr,
            cast(void*) SECRET_SCHEMA_ATTRIBUTE_STRING
        );
        g_hash_table_insert(
            types,
            cast(void*) credentialAttribute.ptr,
            cast(void*) SECRET_SCHEMA_ATTRIBUTE_STRING
        );

        return secret_schema_newv(
            schemaName.ptr,
            SECRET_SCHEMA_NONE,
            types
        );
    }

    private static SecretValue* makeSecretValue(
        scope ref const SecretBuffer secret
    ) @trusted
    {
        SecretValue* result;

        secret.withBytes((scope const(ubyte)[] bytes) @safe
        {
            const(char)* data = bytes.length == 0
                ? "".ptr
                : cast(const(char)*) bytes.ptr;

            result = secret_value_new(
                data,
                cast(gssize) bytes.length,
                binaryContentType.ptr
            );
        });

        return result;
    }

    private static void freeItemList(GList* items) @trusted
    {
        g_list_free_full(
            items,
            cast(void*) &g_object_unref
        );
    }

    private static CredentialStatus consumeError(
        ref GError* error,
        CredentialStatus fallback
    ) @trusted
    {
        if (error is null)
            return fallback;

        CredentialStatus status = fallback;

        if (g_error_matches(
            error,
            secret_error_get_quark(),
            SECRET_ERROR_IS_LOCKED
        ))
        {
            status = CredentialStatus.locked;
        }
        else if (g_error_matches(
            error,
            secret_error_get_quark(),
            SECRET_ERROR_NO_SUCH_OBJECT
        ))
        {
            status = CredentialStatus.notFound;
        }
        else if (g_error_matches(
            error,
            secret_error_get_quark(),
            SECRET_ERROR_ALREADY_EXISTS
        ))
        {
            status = CredentialStatus.ambiguous;
        }
        else if (g_error_matches(
            error,
            g_io_error_quark(),
            G_IO_ERROR_CANCELLED
        ))
        {
            status = CredentialStatus.userCancelled;
        }
        else if (g_error_matches(
            error,
            g_io_error_quark(),
            G_IO_ERROR_PERMISSION_DENIED
        ))
        {
            status = CredentialStatus.permissionDenied;
        }
        else if (g_error_matches(
            error,
            g_io_error_quark(),
            G_IO_ERROR_NOT_SUPPORTED
        ))
        {
            status = CredentialStatus.unsupported;
        }
        else if (
            g_error_matches(
                error,
                g_io_error_quark(),
                G_IO_ERROR_TIMED_OUT
            ) ||
            g_error_matches(
                error,
                g_io_error_quark(),
                G_IO_ERROR_NOT_INITIALIZED
            ) ||
            g_error_matches(
                error,
                g_io_error_quark(),
                G_IO_ERROR_DBUS_ERROR
            ) ||
            g_error_matches(
                error,
                g_io_error_quark(),
                G_IO_ERROR_CONNECTION_REFUSED
            ) ||
            g_error_matches(
                error,
                g_io_error_quark(),
                G_IO_ERROR_NOT_CONNECTED
            )
        )
        {
            status = CredentialStatus.unavailable;
        }

        g_error_free(error);
        error = null;
        return status;
    }

    private void releaseNative() @trusted
    {
        if (service_ !is null)
        {
            g_object_unref(service_);
            service_ = null;
        }

        if (schema_ !is null)
        {
            secret_schema_unref(schema_);
            schema_ = null;
        }
    }
}
