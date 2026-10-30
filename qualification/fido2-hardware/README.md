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

The operator will be asked to touch the key multiple times.

Older PIN-protected CTAP2.0 authenticators may additionally require the PIN
while creating the qualification credential. The runner detects
`interactionRequired`, prompts once, and retries MakeCredential with the PIN.
That PIN is only for credential creation; the subsequent user-presence
hmac-secret derivations remain PIN-less and must return an assertion without
the UV flag.

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

## 4. Two-key / loss-of-key qualification

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

The same mode can be combined with `--uv` if both authenticators support the
UV policy.

## 5. Repeat with LDC

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

## Completion rule

Issue #36 may be closed only after committed or otherwise retained evidence
shows:

- one physical hmac-secret authenticator PASS for user presence;
- UV/PIN PASS on a capable authenticator, or an explicit device-specific
  UNSUPPORTED result plus a PASS on another capable authenticator before
  claiming UV production qualification;
- wrong-authenticator PASS when a second key is available;
- independent backup-key PASS with A physically absent when a second key is
  available;
- both DMD and LDC exercised where practical.

Do not use real application credentials in this fixture.
