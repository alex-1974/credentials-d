/**
 * Common credential-store contract and backend capabilities.
 */
module credentials.store;

import credentials.handle : CredentialHandle;
import credentials.namespace : CredentialNamespace;
import credentials.secret : SecretBuffer;

/**
 * Normal operation outcomes.
 *
 * Status values are non-secret and safe to report in ordinary diagnostics.
 * Backends should reserve exceptions for programmer errors or exceptional
 * runtime failures that cannot be represented by this contract.
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
 * Concurrency contract advertised by a store backend.
 */
enum StoreConcurrency
{
    threadConfined,
    serialized,
    threadSafe
}

/**
 * How credentials are protected at rest by this backend.
 */
enum StoreProtection
{
    memoryOnly,
    operatingSystem,
    encryptedVault
}

/**
 * How access to stored credentials is unlocked.
 */
enum StoreUnlockModel
{
    none,
    operatingSystem,
    application
}

/**
 * Expected mobility of stored credentials.
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
 * Whether normal operations may block or require user interaction.
 */
enum StoreBlocking
{
    nonBlocking,
    mayBlock,
    mayPrompt
}

/**
 * Material security and behavior properties of one store backend.
 *
 * Capabilities describe properties that the backend actually provides. They
 * must not be inferred from platform name or silently upgraded by fallback.
 */
struct StoreCapabilities
{
    /** Whether credentials survive the lifetime of the store instance/process. */
    bool persistent;

    /** Protection used for credential plaintext while persisted. */
    StoreProtection protection;

    /** Who or what controls unlocking of the persisted credentials. */
    StoreUnlockModel unlockModel;

    /** Expected persistence/mobility boundary of stored credentials. */
    StoreMobility mobility;

    /**
     * Whether successful remove() confirms that the logical credential record
     * no longer resolves through this backend.
     *
     * This does not claim forensic erasure of storage media.
     */
    bool confirmsLogicalDeletion;

    /** Whether normal operations can block or prompt the user. */
    StoreBlocking blocking;

    /** Concurrency contract for one store instance. */
    StoreConcurrency concurrency;
}

/**
 * Callback used for explicit plaintext acquisition.
 *
 * The credential bytes are read-only and scoped to the callback invocation.
 */
alias SecretCallback = void delegate(scope const(ubyte)[] bytes) @safe;

/**
 * Application-independent credential persistence boundary.
 *
 * Implementations own record persistence and must honor the security contract
 * in `docs/security/THREAT_MODEL.md`.
 *
 * A store is always bound to one validated application namespace. Handles from
 * a different namespace or store instance must never resolve to a credential
 * by accident.
 *
 * The common interface does not promise thread safety. Callers must inspect
 * `capabilities.concurrency`.
 *
 * credentials-d does not define a fallback chain. If the selected backend is
 * unavailable, the operation reports that condition instead of silently
 * persisting plaintext or switching to a weaker store.
 */
interface CredentialStore
{
    /**
     * Non-secret application namespace owned by this store.
     */
    @property CredentialNamespace credentialNamespace() const
        @nogc nothrow @safe;

    /**
     * Describe backend properties without acquiring a secret.
     */
    @property StoreCapabilities capabilities() const @nogc nothrow @safe;

    /**
     * Persist a new credential and return its non-secret handle.
     *
     * The backend must not retain a reference to `secret` beyond the call.
     * On failure, `handle` is invalid.
     *
     * Params:
     *     secret = Owned secret plaintext to persist.
     *     handle = Receives the opaque non-secret handle on success.
     *
     * Returns:
     *     CredentialStatus.ok on success, otherwise the backend outcome.
     */
    CredentialStatus save(
        scope ref const SecretBuffer secret,
        out CredentialHandle handle
    ) @safe;

    /**
     * Acquire plaintext explicitly for the duration of `callback`.
     *
     * The callback is invoked exactly once on `ok`, and not invoked for any
     * other status. Consumer exceptions propagate normally.
     *
     * Params:
     *     handle = Opaque handle returned by this backend.
     *     callback = Receives a scoped read-only plaintext view.
     *
     * Returns:
     *     CredentialStatus.ok when the callback ran successfully, otherwise
     *     the lookup/backend outcome.
     */
    CredentialStatus withSecret(
        CredentialHandle handle,
        scope SecretCallback callback
    ) @safe;

    /**
     * Replace the credential referenced by `handle`.
     *
     * Replacement never returns the previous plaintext.
     *
     * Params:
     *     handle = Opaque handle of the credential to replace.
     *     replacement = New secret plaintext.
     *
     * Returns:
     *     CredentialStatus.ok on success, notFound if the record no longer
     *     exists, or another backend outcome.
     */
    CredentialStatus update(
        CredentialHandle handle,
        scope ref const SecretBuffer replacement
    ) @safe;

    /**
     * Remove the logical credential record.
     *
     * `notFound` means the handle does not identify a current record.
     * Physical media erasure is not implied.
     *
     * Params:
     *     handle = Opaque handle of the credential to remove.
     *
     * Returns:
     *     CredentialStatus.ok when the logical record was removed.
     */
    CredentialStatus remove(CredentialHandle handle) @safe;
}
