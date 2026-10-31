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
    ok,
    notFound,
    locked,
    userActionRequired,
    userCancelled,
    unavailable,
    permissionDenied,
    unsupported,
    tooLarge,
    multipleMatches,
    corruptedData,
    writeOutcomeUnknown,
    invalidInput,
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
    bool persistent;
    StoreProtection protection;
    StoreUnlockModel unlockModel;
    StoreMobility mobility;
    bool confirmsLogicalDeletion;
    StoreBlocking blocking;
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
     */
    CredentialStatus withSecret(
        CredentialHandle handle,
        scope SecretCallback callback
    ) @safe;

    /**
     * Replace the credential referenced by `handle`.
     *
     * Replacement never returns the previous plaintext.
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
     */
    CredentialStatus remove(CredentialHandle handle) @safe;
}
