/**
 * Narrow C ABI surface for libsecret/GLib used by the Linux backend.
 *
 * Keep this module internal. Public consumers use LinuxSecretServiceStore.
 */
module credentials.backend.secret_service.ffi;

version (linux):

import core.stdc.stddef : ptrdiff_t;

alias gboolean = int;
alias gint = int;
alias guint = uint;
alias gsize = size_t;
alias gssize = ptrdiff_t;
alias GQuark = uint;
alias GType = size_t;

struct SecretService;
struct SecretSchema;
struct SecretValue;
struct SecretItem;
struct GHashTable;
struct GList;
struct GCancellable;
struct GError;

enum int SECRET_SCHEMA_NONE = 0;
enum int SECRET_SCHEMA_ATTRIBUTE_STRING = 0;

enum int SECRET_SERVICE_OPEN_SESSION = 1 << 1;

enum int SECRET_SEARCH_ALL = 1 << 1;
enum int SECRET_SEARCH_UNLOCK = 1 << 2;
enum int SECRET_SEARCH_LOAD_SECRETS = 1 << 3;

enum int SECRET_ERROR_PROTOCOL = 1;
enum int SECRET_ERROR_IS_LOCKED = 2;
enum int SECRET_ERROR_NO_SUCH_OBJECT = 3;
enum int SECRET_ERROR_ALREADY_EXISTS = 4;

enum int G_IO_ERROR_PERMISSION_DENIED = 14;
enum int G_IO_ERROR_NOT_SUPPORTED = 15;
enum int G_IO_ERROR_CANCELLED = 19;
enum int G_IO_ERROR_NOT_INITIALIZED = 32;
enum int G_IO_ERROR_DBUS_ERROR = 36;
enum int G_IO_ERROR_CONNECTION_REFUSED = 39;
enum int G_IO_ERROR_NOT_CONNECTED = 45;
enum int G_IO_ERROR_TIMED_OUT = 24;

extern(C) @nogc nothrow
{
    // GLib hash/list/error helpers.
    GHashTable* g_hash_table_new_full(
        void* hashFunc,
        void* keyEqualFunc,
        void* keyDestroyFunc,
        void* valueDestroyFunc
    );
    gboolean g_hash_table_insert(
        GHashTable* hashTable,
        void* key,
        void* value
    );
    void g_hash_table_unref(GHashTable* hashTable);

    guint g_str_hash(const(void)* value);
    gboolean g_str_equal(const(void)* first, const(void)* second);
    char* g_strdup(scope const(char)* text);
    void g_free(void* memory);

    guint g_list_length(GList* list);
    void* g_list_nth_data(GList* list, guint n);
    void g_list_free_full(GList* list, void* freeFunc);

    gboolean g_error_matches(
        const GError* error,
        GQuark domain,
        gint code
    );
    void g_error_free(GError* error);

    GQuark g_io_error_quark();

    // GObject ownership.
    void* g_object_ref(void* object);
    void g_object_unref(void* object);

    // Schema and error domain.
    SecretSchema* secret_schema_newv(
        scope const(char)* name,
        int flags,
        GHashTable* attributeNamesAndTypes
    );
    void secret_schema_unref(SecretSchema* schema);
    GQuark secret_error_get_quark();

    // Service/session.
    GType secret_service_get_type();
    SecretService* secret_service_open_sync(
        GType serviceGType,
        scope const(char)* serviceBusName,
        int flags,
        GCancellable* cancellable,
        GError** error
    );

    GList* secret_service_search_sync(
        SecretService* service,
        const SecretSchema* schema,
        GHashTable* attributes,
        int flags,
        GCancellable* cancellable,
        GError** error
    );

    gboolean secret_service_store_sync(
        SecretService* service,
        const SecretSchema* schema,
        GHashTable* attributes,
        scope const(char)* collection,
        scope const(char)* label,
        SecretValue* value,
        GCancellable* cancellable,
        GError** error
    );

    // Item operations.
    gboolean secret_item_get_locked(SecretItem* item);
    SecretValue* secret_item_get_secret(SecretItem* item);
    gboolean secret_item_load_secret_sync(
        SecretItem* item,
        GCancellable* cancellable,
        GError** error
    );
    gboolean secret_item_set_secret_sync(
        SecretItem* item,
        SecretValue* value,
        GCancellable* cancellable,
        GError** error
    );
    gboolean secret_item_delete_sync(
        SecretItem* item,
        GCancellable* cancellable,
        GError** error
    );

    // Binary secret values.
    SecretValue* secret_value_new(
        scope const(char)* secret,
        gssize length,
        scope const(char)* contentType
    );
    const(char)* secret_value_get(
        SecretValue* value,
        gsize* length
    );
    void secret_value_unref(SecretValue* value);
}
