/**
 * Public Linux credential-store API.
 */
module credentials.linux;

import credentials.namespace : CredentialNamespace;
import credentials.backend.secret_service.store :
    LinuxSecretServiceStore;

/**
 * Credential store backed by the desktop operating-system credential service.
 *
 * Construct one instance per application credential namespace.
 *
 * Examples:
 * ---
 * auto ns = CredentialNamespace("org.example.application");
 * auto store = new LinuxCredentialStore(ns);
 * scope(exit) store.close();
 * ---
 */
alias LinuxCredentialStore = LinuxSecretServiceStore;
