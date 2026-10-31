/**
 * Credential storage for Windows applications.
 *
 * Use WindowsCredentialStore when credentials should remain available to the
 * current Windows user across application runs.
 *
 * Examples:
 * ---
 * import credentials :
 *     CredentialHandle,
 *     CredentialNamespace;
 *
 * auto store = new WindowsCredentialStore(
 *     CredentialNamespace("org.example.application")
 * );
 *
 * CredentialHandle handle;
 * store.save(secret, handle);
 * ---
 */
module credentials.windows;

public import credentials.backend.windows.store :
    WindowsCredentialStore;
