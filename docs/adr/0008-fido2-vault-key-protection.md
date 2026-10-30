# ADR 0008 — FIDO2 hmac-secret vault-key protection

**Status:** Accepted for Issue #35  
**Date:** 2026-10-30

## Context

The encrypted vault already separates the passphrase-derived key-encryption key
from the random 256-bit vault key.

That separation makes hardware-assisted unlock possible without storing
application credentials on a security key and without re-encrypting the vault
payload.

FIDO2/CTAP defines the `hmac-secret` extension specifically so a platform can
retrieve a credential-scoped symmetric secret for encryption or decryption.
libfido2 exposes this extension through a stable C API.

## Decision

Add FIDO2 as an optional **vault-key protector**, not as a
`CredentialStore`.

The authenticator stores/derives a FIDO2 credential secret. It does not store
OAuth tokens, API keys, vault records, or the vault key itself.

The model is:

```text
FIDO2 credential + 32-byte envelope salt
                │
                ▼
         CTAP hmac-secret
                │
                ▼
      32-byte wrapping key
                │
                ▼
       XChaCha20-Poly1305
                │
                ▼
       random 256-bit vault key
                │
                ▼
      authenticated vault payload
```

The existing Argon2id/passphrase wrapper remains a recovery path.

Multiple independent protector envelopes may wrap the same vault key.

## Package boundary

FIDO2 support is an explicit optional DUB subpackage:

```text
credentials-d:fido2-vault
```

It depends on:

- `credentials-d:encrypted-vault`;
- official libfido2.

The root package and native credential-store backends do not acquire a
libfido2 dependency.

## libfido2 boundary

credentials-d does not implement CTAP, CBOR, USB HID, NFC, authenticator PIN
protocols, or assertion transport.

A narrow private FFI declares only the operations needed for:

- device discovery;
- credential creation;
- hmac-secret enablement;
- credential id retrieval;
- assertion with one allowed credential;
- one 32-byte hmac-secret salt/output;
- user-presence/user-verification policy;
- timeout/cancel/cleanup.

The implementation initializes libfido2 with U2F fallback disabled.

The current upstream libfido2 release at qualification time is 1.17.0. The
required hmac-secret surface predates that release, so distro security-backed
versions may also qualify if the required ABI and behavior are present.

## Protector binding

A `Fido2VaultBinding` contains only non-secret persistent metadata:

- RP id;
- credential id;
- verification policy;
- format version.

Authenticator device paths are explicitly excluded. Paths are runtime
selectors and may change across boots, ports, operating systems, or device
enumerations.

Bindings are bounded and canonically serialized.

## RP id

The RP id is supplied by the consumer when enrolling the protector.

credentials-d validates a conservative lowercase DNS-like syntax and maximum
length. The RP id is part of authenticator credential scope and therefore part
of the security binding.

Changing it makes the protector unusable rather than selecting another
credential silently.

## User interaction policy

Two policies exist:

### userPresence

- assertion explicitly requires user presence;
- the CTAP `uv` option is omitted rather than sending `uv=false`, because
  authenticators that do not advertise built-in UV must not receive that
  option;
- after GetAssertion, the returned authenticator-data flags are checked and an
  unexpected UV bit is rejected;
- some PIN-protected CTAP2.0 authenticators may require PIN authorization for
  MakeCredential even though later hmac-secret assertions remain
  user-presence-only.

A PIN supplied for this CTAP2.0 MakeCredential compatibility case authorizes
credential creation only. It does not change the persisted policy and is not
used for later hmac-secret derivation.

This keeps the hmac-secret derivation consistently in the non-UV branch while
remaining compatible with older PIN-protected CTAP2 authenticators.

### userVerificationRequired

- enrollment requests UV;
- enrollment requests `credProtect=UV_REQUIRED`;
- assertion requests both user presence and UV;
- a PIN may be supplied through `SecretBuffer`.

If the authenticator cannot satisfy the requested UV/credProtect policy,
enrollment fails. The implementation does not silently downgrade to touch-only.

This distinction matters because hmac-secret output may differ depending on
whether authenticator user verification was performed.

## PIN handling

libfido2 accepts PINs as NUL-terminated UTF-8 strings.

credentials-d therefore:

1. accepts PIN bytes through `SecretBuffer`;
2. rejects empty, embedded-NUL, or unreasonably long inputs;
3. allocates one temporary native buffer;
4. appends the required NUL terminator;
5. performs the synchronous libfido2 operation;
6. overwrites every byte with compiler-recognized volatile stores;
7. frees the buffer.

The library cannot erase copies created before the PIN entered
`SecretBuffer`.

PINs are never persisted in a FIDO2 binding or unlock envelope.

For PIN-protected CTAP2.0 authenticators, `interactionRequired` from an
initial userPresence enrollment is an explicit signal that the caller may
retry MakeCredential through the PIN overload while retaining the
userPresence policy.

## External vault unlock envelope

FIDO2 does not modify encrypted-vault format version 1.

Instead, `VaultUnlockEnvelope` is a small independently persistable,
non-secret wrapper containing:

- envelope magic/version;
- protector kind;
- opaque protector binding;
- vault id;
- random 32-byte protector salt;
- random XChaCha20 nonce;
- AEAD-wrapped vault key.

Associated data binds:

- credential namespace;
- protector kind;
- protector binding;
- vault id;
- protector salt;
- envelope format domain/version.

A changed credential id, RP id, UV policy, namespace, vault id, or protector
kind therefore causes authentication failure.

The envelope may be copied with the vault; confidentiality still depends on the
FIDO2 credential-derived wrapping key.

## Double authentication

A successfully decrypted envelope is not by itself sufficient to unlock.

After recovering the candidate vault key, the encrypted-vault backend uses it
to authenticate/decrypt the actual vault payload and parse the complete record
table.

A malicious or wrong authenticator can therefore cause unlock failure but
cannot inject an arbitrary accepted vault key.

## Multiple protectors and recovery

Several envelopes may wrap the same vault key, for example:

```text
vault key
  ├── passphrase/Argon2id wrapper   (inside vault v1)
  ├── FIDO2 key A envelope
  └── FIDO2 backup key B envelope
```

Loss of one FIDO2 key does not require re-encrypting credential records and
does not destroy the vault while another wrapper remains available.

Version 1 does not support FIDO2-only vaults because the passphrase wrapper is
still part of the vault file. Removing the recovery wrapper would require a
new separately reviewed format/policy.

## Synchronous/blocking behavior

libfido2 makeCredential/getAssertion operations are synchronous and may block
for user interaction.

The FIDO2 protector uses a bounded operation timeout and must not be called on a
GUI/render thread.

No background thread or task framework is introduced into credentials-d.

## Error handling

libfido2/CTAP error codes are mapped into the existing non-secret
`CredentialStatus` categories.

Notably:

- PIN/UV failures -> `permissionDenied`;
- PIN/user-presence requirement -> `interactionRequired`;
- user cancellation/timeouts -> `userCancelled`;
- missing credential -> `notFound`;
- unsupported extension/policy -> `unsupported`;
- transport/internal failures -> `backendFailure`.

Native error strings and secret material are not propagated through the public
API.

## Security limits

FIDO2 hardware assistance does not protect against:

- hostile code controlling the process after vault unlock;
- root/administrator or a compromised OS;
- deliberate export/copy by the consumer inside scoped plaintext callbacks;
- loss of every configured unlock/recovery factor.

A cloned authenticator credential, where the authenticator ecosystem permits
one, inherits the same ability to derive its credential-scoped secret.

## Verification

Normal CI can prove:

- FIDO2 binding parsing/serialization;
- narrow FFI compilation/linking;
- libfido2 discovery ABI;
- envelope cryptographic round-trip with deterministic key sources;
- wrong wrapping key rejection;
- binding tamper rejection;
- multiple wrappers;
- passphrase recovery remains valid;
- DMD/LDC/DIP1000 compatibility.

A real physical-authenticator qualification is separately required for:

- MakeCredential with hmac-secret;
- user-presence policy;
- UV + credProtect policy;
- PIN handling;
- GetAssertion hmac-secret stability;
- key removal/wrong-key behavior.

## References

- FIDO Alliance, Client to Authenticator Protocol (CTAP), hmac-secret:
  https://fidoalliance.org/specs/
- libfido2:
  https://github.com/Yubico/libfido2
- libfido2 manuals:
  https://developers.yubico.com/libfido2/Manuals/
