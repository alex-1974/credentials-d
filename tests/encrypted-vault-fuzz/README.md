# Encrypted-vault header fuzz target

This package contains a libFuzzer-compatible
`LLVMFuzzerTestOneInput` entrypoint for the versioned encrypted-vault header
parser.

The target is intentionally narrow:

- arbitrary input bytes only;
- fixed non-secret test namespace;
- no passphrase;
- no Argon2 invocation;
- no payload decryption;
- no plaintext visitor.

The regular CI gate compiles this target under the baseline DMD and LDC
toolchains. The deterministic malformed-input corpus in the encrypted-vault
unit tests remains the fast regression gate.

Long-running fuzz campaigns should link this static target with a
libFuzzer-capable LDC/LLVM toolchain in a dedicated fuzzing environment. Fuzzer
artifacts must be reduced to non-secret synthetic regression inputs before
being committed.
