/**
 * Public macOS credential-store API.
 */
module credentials.macos;

import credentials.backend.macos.store :
    MacOSDataProtectionCredentialStore;

/**
 * Credential store backed by the macOS system credential service.
 */
alias MacOSCredentialStore = MacOSDataProtectionCredentialStore;
