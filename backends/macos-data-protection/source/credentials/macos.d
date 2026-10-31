/**
 * Public macOS credential-store API.
 */
module credentials.macos;

import credentials.namespace : CredentialNamespace;
import credentials.backend.macos.store :
    MacOSDataProtectionCredentialStore;

/**
 * Credential store backed by the macOS system credential service.
 *
 * A properly signed/provisioned application context is required for production
 * Data Protection Keychain use.
 *
 * Examples:
 * ---
 * auto ns = CredentialNamespace("org.example.application");
 * auto store = new MacOSCredentialStore(ns);
 * ---
 */
alias MacOSCredentialStore = MacOSDataProtectionCredentialStore;
