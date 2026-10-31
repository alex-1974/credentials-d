# FIDO2 physical-authenticator qualification

This fixture is the production-evidence runner for issue #36.

It deliberately requires a physical authenticator. CI only compiles this
fixture and exercises the separate no-hardware discovery path; CI never
pretends that a virtual or absent authenticator proves the hardware contract.

## Dependencies

On Ubuntu/Debian:

```bash
sudo apt-get install libfido2-dev libsodium-dev
```

Use the same baseline compilers as the library where practical:

```text
DMD 2.111.0
LDC 1.41.0
```

## 1. Discover authenticators

```bash
cd qualification/fido2-hardware
DC=dmd ./run.sh --discover-only
```

Discovery prints runtime device paths so an operator can select a device. The
path is not persisted inside `Fido2VaultBinding`, `VaultUnlockEnvelope`, or
the qualification PASS receipt fields.

Discovery also prints standard CTAP capabilities for each authenticator:
hmac-secret/hmac-secret-mc, credProtect, PIN/UV state, UV modality,
discoverable-credential support/capacity, ES256/EdDSA/ES384/RS256 support and
the raw firmware-version value. This GetInfo query does not require touch or
PIN entry.

## 2. User-presence qualification

Use a synthetic RP id dedicated to this qualification. The default is
`credentials-d.local`.

```bash
DC=dmd ./run.sh
```

If exactly one FIDO2 authenticator is discoverable, the runner selects it
automatically. This avoids relying on unstable `/dev/hidrawN` numbering.
`--device-a /dev/hidrawN` remains available when several devices are
attached.

The qualification runner reports the envelope enrollment path. On a device
with `hmac-secret-mc` it prints
`Envelope_A_enrollment_path=hmac-secret-mc` and expects one combined
MakeCredential/key-derivation interaction. On older devices it prints
`makecredential-plus-getassertion` and retains the two explicit interactions.

The operator is prompted before every individual operation that can require
user presence. For each prompt, release the sensor, wait until the authenticator
starts blinking, then touch once. This avoids visually conflating consecutive
CTAP operations into one apparently slow touch.

Older PIN-protected CTAP2.0 authenticators may additionally require the PIN
while creating the qualification credential. The runner detects
`interactionRequired`, prompts once, and retries MakeCredential with the PIN.
That PIN is only for credential creation; the subsequent user-presence
hmac-secret derivations remain PIN-less and must return an assertion without
the UV flag.

The public API exposes the same lifecycle explicitly through
`addFido2TouchVaultUnlockWithEnrollmentPin()` for one-time setup and
`unlockVaultWithFido2Touch()` for normal use. The latter accepts no PIN and
therefore represents a strict authenticator-touch-only unlock path.

YubiKeys with firmware before 5.3.0 also require a UserEntity name even though
CTAP makes it optional in this privacy-preserving UP-only case. The library
uses the constant non-personal value `credentials-d`; the random user id
remains the credential-specific identifier.

The run proves:

- non-resident hmac-secret credential enrollment;
- same credential + same 32-byte salt => same hmac-secret output;
- changed salt => changed output;
- runtime device path is absent from the persisted binding;
- binary synthetic credential storage;
- envelope serialization and reopen;
- FIDO2 unlock of a fresh vault instance;
- ciphertext/envelope tamper rejection;
- passphrase recovery remains valid.

## 3. UV / PIN qualification

```bash
DC=dmd ./run.sh \
  --uv \
  --device-a /dev/hidrawN
```

The launcher disables terminal echo for every interactive qualification run,
because a PIN can also be required by older CTAP2.0 authenticators during the
user-presence MakeCredential step. The PIN is never placed in argv or the
receipt.

The UV run additionally proves:

- enrollment requests UV and `credProtect=UV_REQUIRED`;
- hmac-secret derivation remains deterministic in the UV branch;
- one deliberately wrong PIN attempt maps to `permissionDenied`;
- no plaintext PIN is printed.

A device that cannot satisfy the requested UV/credProtect policy produces an
explicit `result=UNSUPPORTED`; that is evidence about the authenticator, not a
permission to downgrade to touch-only.

**Warning:** the UV qualification intentionally performs exactly one wrong-PIN
attempt. Do not repeatedly run the wrong-PIN portion on a device with very low
remaining retry count.

## 4. Built-in UV qualification

Use this mode only with an authenticator that reports built-in UV as supported
and configured, for example a biometric authenticator:

```bash
DC=dmd ./run.sh \
  --uv-built-in \
  --device-a /dev/hidrawN
```

This mode supplies no PIN to libfido2. Enrollment and assertion still request
UV and `credProtect=UV_REQUIRED`; the authenticator must satisfy UV internally.
If built-in UV is absent or not configured, the runner returns
`result=UNSUPPORTED` rather than falling back to PIN or touch-only.

The run proves the same hmac-secret, envelope, tamper and recovery properties
as the normal qualification path while exercising the explicit PIN-free
`userVerificationRequired` API.

## 5. Two-key / loss-of-key qualification

Attach two independent authenticators and discover both paths first.

```bash
DC=dmd ./run.sh \
  --device-a /dev/hidrawA \
  --device-b /dev/hidrawB \
  --confirm-remove-a
```

The fixture:

1. creates envelope A;
2. proves key B cannot unlock envelope A;
3. recovers by passphrase;
4. creates independent envelope B for the same random vault key;
5. asks the operator to unplug key A;
6. re-discovers devices and verifies A is absent;
7. unlocks with B and reads the original synthetic credential.

The same mode can be combined with `--uv` for PIN-based UV, or with
`--uv-built-in` when both authenticators support and have configured built-in
UV.

## 6. Repeat with LDC

Repeat the relevant production run with:

```bash
DC=ldc2 ./run.sh ...
```

Receipts are written under:

```text
qualification-results/fido2/
```

That directory is intentionally ignored by Git. A receipt contains compiler,
OS, native-library versions, non-secret authenticator product/manufacturer
metadata and PASS/SKIP/UNSUPPORTED results. It contains no PIN, hmac-secret,
vault key, credential plaintext, or serialized envelope.

## Qualification status

Issue #36 was completed on 2026-10-31. Physical evidence on a YubiKey 5.2.4
established hmac-secret enrollment and derivation, touch-only/user-presence,
UV/PIN, wrong-PIN rejection, vault reopen/unlock, tamper rejection, independent
wrong-credential rejection and passphrase recovery.

DMD 2.111.0 was exercised physically. The locally installed LDC 1.42.0 was
also exercised physically; CI covers the supported LDC 1.41.0 baseline.

The optional second-authenticator scenarios were skipped because no second
physical key was available. They are not part of the qualified claim.

The prompt-per-touch changes in this fixture are interaction/observability
hardening only; they do not change the qualified FIDO2 protocol or vault
cryptography.

Do not use real application credentials in this fixture.
