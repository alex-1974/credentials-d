/**
 * Common API for saving, reading, updating and removing application
 * credentials.
 *
 * Write application code against CredentialStore when the same credential
 * workflow should work with different storage choices.
 */
module credentials.store;

import credentials.handle : CredentialHandle;
import credentials.namespace : CredentialNamespace;
import credentials.secret : SecretBuffer;

/**
 * Result of a credential-store operation.
 *
 * Most application flows need to handle only a small subset, typically ok,
 * notFound, locked, userCancelled and unavailable. The remaining values let
 * applications distinguish errors when they need more specific recovery.
 */
enum CredentialStatus
{
    /** Operation completed successfully. */
    ok,

    /** The requested credential does not exist. */
    notFound,

    /** The selected store or vault is currently locked. */
    locked,

    /** The operation requires an explicit user action before it can continue. */
    userActionRequired,

    /** The user cancelled an interactive operation. */
    userCancelled,

    /** The selected storage service or device is currently unavailable. */
    unavailable,

    /** The caller or application is not permitted to perform the operation. */
    permissionDenied,

    /** The selected backend cannot provide the requested operation or policy. */
    unsupported,

    /** The supplied secret or persisted object exceeds a supported size limit. */
    tooLarge,

    /** More than one stored record matched where exactly one was required. */
    multipleMatches,

    /** Persisted data failed structural or authenticated validation. */
    corruptedData,

    /**
     * A write was attempted but the backend cannot prove whether it committed.
     *
     * Consumers must not blindly retry an operation that could create a
     * duplicate record. Re-read or reconcile persistent state first.
     */
    writeOutcomeUnknown,

    /** Caller-supplied input is malformed, invalid, or belongs elsewhere. */
    invalidInput,

    /** The storage backend failed for a reason not represented above. */
    storageFailure
}

/**
 * How one store instance may be used from multiple threads.
 *
 * Check this when deciding whether your application may share one store
 * instance between workers.
 */
enum StoreConcurrency
{
    threadConfined,
    serialized,
    threadSafe
}

/**
 * Where responsibility for protecting stored credentials lies.
 *
 * This is useful when an application offers users more than one storage
 * choice.
 */
enum StoreProtection
{
    memoryOnly,
    operatingSystem,
    encryptedVault
}

/**
 * Who controls access to stored credentials.
 *
 * Use this when the UI needs to explain whether unlocking is handled by the
 * operating system or by the application itself.
 */
enum StoreUnlockModel
{
    none,
    operatingSystem,
    application
}

/**
 * Where stored credentials may be available.
 *
 * This helps an application distinguish process-only, device-local, portable
 * and potentially synchronized storage.
 */
enum StoreMobility
{
    processOnly,
    localDevice,
    portableFile,
    mayRoam,
    synchronizable
}

/**
 * Whether normal store operations can block or show user interaction.
 *
 * GUI applications can use this to decide whether an operation belongs on a
 * worker thread.
 */
enum StoreBlocking
{
    nonBlocking,
    mayBlock,
    mayPrompt
}

/**
 * Properties of one credential store that can affect application behavior.
 *
 * Read capabilities when choosing a store, presenting storage options to the
 * user, or deciding where an operation should run.
 *
 * Examples:
 * ---
 * const caps = store.capabilities;
 *
 * if (caps.blocking == StoreBlocking.mayPrompt)
 * {
 *     // Run the operation away from the render/UI thread.
 * }
 * ---
 */
struct StoreCapabilities
{
    /** Whether saved credentials are intended to survive application restart. */
    bool persistent;

    /** Where protection of saved credentials is provided. */
    StoreProtection protection;

    /** Who controls unlocking before saved credentials can be used. */
    StoreUnlockModel unlockModel;

    /** Where saved credentials may become available. */
    StoreMobility mobility;

    /**
     * Whether successful remove() means this store will no longer return the
     * credential.
     */
    bool confirmsLogicalDeletion;

    /** Whether normal operations can block or ask the user to interact. */
    StoreBlocking blocking;

    /** How one store instance may be shared between threads. */
    StoreConcurrency concurrency;
}

/**
 * Function that receives a credential while it is being used.
 *
 * Keep work that needs the secret inside this callback instead of copying the
 * bytes into long-lived application state.
 */
alias SecretCallback = void delegate(scope const(ubyte)[] bytes) @safe;

/**
 * Common credential-store interface.
 *
 * Use this type when application logic should not care whether credentials are
 * stored by Linux, Windows, macOS, an encrypted vault or a test store.
 *
 * Every store belongs to one CredentialNamespace and returns CredentialHandle
 * values that can be persisted in normal application settings.
 *
 * Examples:
 * ---
 * CredentialHandle handle;
 *
 * auto status = store.save(secret, handle);
 *
 * if (status == CredentialStatus.ok)
 * {
 *     status = store.withSecret(
 *         handle,
 *         (scope const(ubyte)[] bytes) @safe
 *         {
 *             // Use the credential here.
 *         }
 *     );
 * }
 * ---
 */
interface CredentialStore
{
    /**
     * Application namespace this store belongs to.
     *
     * Persist or compare the namespace only through CredentialNamespace.
     */
    @property CredentialNamespace credentialNamespace() const
        @nogc nothrow @safe;

    /**
     * Describe how this store behaves.
     *
     * Use this before scheduling operations or presenting storage choices.
     */
    @property StoreCapabilities capabilities() const @nogc nothrow @safe;

    /**
     * Save a new credential.
     *
     * Persist handle.serialize() in normal application settings so the
     * credential can be found again on the next run.
     *
     * Params:
     *     secret = Credential to save.
     *     handle = Receives the non-secret handle on success.
     *
     * Returns:
     *     ok on success. handle is invalid for any other result.
     *
     * Examples:
     * ---
     * CredentialHandle handle;
     * auto status = store.save(secret, handle);
     *
     * if (status == CredentialStatus.ok)
     *     settings.credentialHandle = handle.serialize();
     * ---
     */
    CredentialStatus save(
        scope ref const SecretBuffer secret,
        out CredentialHandle handle
    ) @safe;

    /**
     * Use a saved credential.
     *
     * Put the operation that needs the credential inside callback. The callback
     * is called only when the credential was found and made available.
     *
     * Params:
     *     handle = Handle returned by save() or restored with tryParse().
     *     callback = Code that uses the credential.
     *
     * Returns:
     *     ok when callback ran; otherwise the reason the credential could not
     *     be provided.
     *
     * Examples:
     * ---
     * auto status = store.withSecret(
     *     handle,
     *     (scope const(ubyte)[] token) @safe
     *     {
     *         // Send the request that needs token.
     *     }
     * );
     * ---
     */
    CredentialStatus withSecret(
        CredentialHandle handle,
        scope SecretCallback callback
    ) @safe;

    /**
     * Replace the value of an existing credential.
     *
     * The existing handle stays valid after a successful update.
     *
     * Params:
     *     handle = Credential to update.
     *     replacement = New credential value.
     *
     * Returns:
     *     ok on success or notFound when the saved credential no longer exists.
     *
     * Examples:
     * ---
     * auto replacement = SecretBuffer(newTokenBytes);
     * auto status = store.update(handle, replacement);
     * ---
     */
    CredentialStatus update(
        CredentialHandle handle,
        scope ref const SecretBuffer replacement
    ) @safe;

    /**
     * Remove a saved credential.
     *
     * After ok, remove the serialized handle from application settings too.
     *
     * Params:
     *     handle = Credential to remove.
     *
     * Returns:
     *     ok when removed or notFound when it was already absent.
     *
     * Examples:
     * ---
     * if (store.remove(handle) == CredentialStatus.ok)
     *     settings.credentialHandle = null;
     * ---
     */
    CredentialStatus remove(CredentialHandle handle) @safe;
}
