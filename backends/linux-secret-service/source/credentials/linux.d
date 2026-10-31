/**
 * Credential storage for Linux desktop applications.
 *
 * Use LinuxCredentialStore for the normal persistent credential store on a
 * Linux desktop.
 */
module credentials.linux;

import credentials.namespace : CredentialNamespace;
import credentials.backend.secret_service.store :
    LinuxSecretServiceStore;

/**
 * Persistent Linux credential store.
 *
 * Create one store for your application's CredentialNamespace. Call close()
 * when the application is finished with the store.
 *
 * Examples:
 * ---
 * auto ns = CredentialNamespace("org.example.application");
 * auto store = new LinuxCredentialStore(ns);
 * scope(exit) store.close();
 *
 * CredentialHandle handle;
 * store.save(secret, handle);
 * ---
 */
alias LinuxCredentialStore = LinuxSecretServiceStore;
