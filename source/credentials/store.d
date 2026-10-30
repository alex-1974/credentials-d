/**
 * Common credential-store contract and backend capabilities.
 */
module credentials.store;

import credentials.handle : CredentialHandle;
import credentials.secret : SecretBuffer;

/**
 * Normal operation outcomes.
 *
 * Status values are non-secret and may be used in diagnostics. Backends should
 * reserve exceptions for programmer errors or exceptional runtime failures
 * that cannot be represented by this contract.
 */
enum CredentialStatus
{
    ok,
    notFound,
    locked,
    unsupported,
    invalidInput,
    backendError
}

/**
 * Concurrency contract advertised by a store backend.
 */
enum StoreConcurrency
{
    threadConfined,
    threadSafe
}

/**
 * Material security and behavior properties of one store backend.
 *
 * A false capability is not a failure; consumers use this structure to avoid
 * assuming protection that the backend does not provide.
 */
struct StoreCapabilities
{
    bool persistent;
    bool supportsLocking;
    bool applicationControlledUnlock;
    bool userPresence;
    bool hardwareBacked;
    bool nativeOsStore;
    bool confirmsLogicalDeletion;
    StoreConcurrency concurrency;
}

/**
 * Callback used for explicit plaintext acquisition.
 *
 * The credential bytes are read-only and scoped to the callback invocation.
 */
alias SecretVisitor = void delegate(scope const(ubyte)[] bytes) @safe;

/**
 * Application-independent credential persistence boundary.
 *
 * Implementations own record persistence and must honor the security contract
 * in `docs/security/THREAT_MODEL.md`.
 *
 * The common interface does not promise thread safety. Callers must inspect
 * `capabilities.concurrency`.
 */
interface CredentialStore
{
    /**
     * Describe backend properties without acquiring a secret.
     */
    @property StoreCapabilities capabilities() const @nogc nothrow @safe;

    /**
     * Persist a new credential and return its non-secret handle.
     *
     * The backend copies only the plaintext bytes required for persistence and
     * must not retain the `SecretBuffer` object itself.
     *
     * On failure, `handle` is invalid.
     */
    CredentialStatus store(scope SecretBuffer secret, out CredentialHandle handle) @safe;

    /**
     * Acquire plaintext explicitly for the duration of `visitor`.
     *
     * The visitor is invoked exactly once on `ok`, and not invoked for any
     * other status. Consumer exceptions propagate normally.
     */
    CredentialStatus acquire(
        CredentialHandle handle,
        scope SecretVisitor visitor
    ) @safe;

    /**
     * Replace the credential referenced by `handle`.
     *
     * Replacement never returns the previous plaintext.
     */
    CredentialStatus replace(
        CredentialHandle handle,
        scope SecretBuffer replacement
    ) @safe;

    /**
     * Remove the logical credential record.
     *
     * `notFound` means the handle does not identify a current record.
     * Physical media erasure is not implied.
     */
    CredentialStatus remove(CredentialHandle handle) @safe;
}
