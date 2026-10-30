/**
 * libFuzzer-compatible entrypoint for the bounded vault header parser.
 *
 * This target deliberately exercises only structural parsing. It does not
 * accept a passphrase, invoke Argon2, decrypt payload data, or expose a
 * SecretVisitor.
 */
module credentials.backend.vault.header_fuzz;

import credentials.backend.vault.core :
    validateVaultImageHeader;
import credentials.namespace : CredentialNamespace;

/**
 * Standard libFuzzer entrypoint.
 *
 * Fuzz input is untrusted arbitrary bytes. A null pointer with non-zero length
 * is outside libFuzzer's input contract and is rejected defensively.
 */
extern(C) int LLVMFuzzerTestOneInput(
    const(ubyte)* data,
    size_t size
) @trusted
{
    if (size != 0 && data is null)
        return 0;

    CredentialNamespace ns;
    if (!CredentialNamespace.tryParse(
        "org.example.credentials-vault-fuzz",
        ns
    ))
        return 0;

    const(ubyte)[] input;
    if (size != 0)
        input = data[0 .. size];

    // Any malformed-input result is valid. Crashes, bounds violations or
    // uncaught parser failures are the fuzzing signal.
    validateVaultImageHeader(input, ns);
    return 0;
}
