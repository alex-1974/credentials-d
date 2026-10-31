/**
 * Credential storage for macOS applications.
 *
 * Use MacOSCredentialStore for persistent application credentials on macOS.
 */
module credentials.macos;

import credentials.namespace : CredentialNamespace;
import credentials.backend.macos.store :
    MacOSDataProtectionCredentialStore;

/**
 * Persistent macOS credential store.
 *
 * Production applications must run in the signing/provisioning context needed
 * by macOS for this store.
 *
 * Examples:
 * ---
 * auto store = new MacOSCredentialStore(
 *     CredentialNamespace("org.example.application")
 * );
 *
 * CredentialHandle handle;
 * store.save(secret, handle);
 * ---
 */
alias MacOSCredentialStore = MacOSDataProtectionCredentialStore;
