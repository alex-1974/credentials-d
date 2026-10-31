/**
 * Public Linux credential-store API.
 */
module credentials.linux;

import credentials.backend.secret_service.store :
    LinuxSecretServiceStore;

/**
 * Credential store backed by the desktop operating-system credential service.
 */
alias LinuxCredentialStore = LinuxSecretServiceStore;
