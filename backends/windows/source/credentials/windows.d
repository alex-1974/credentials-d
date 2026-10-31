/**
 * Public Windows credential-store API.
 *
 * Examples:
 * ---
 * import credentials : CredentialNamespace;
 *
 * auto ns = CredentialNamespace("org.example.application");
 * auto store = new WindowsCredentialStore(ns);
 * ---
 */
module credentials.windows;

public import credentials.backend.windows.store :
    WindowsCredentialStore;
