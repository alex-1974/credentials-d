# Native platform credential-store qualification

**Status:** Accepted for Issue #3  
**Date:** 2026-10-30

This document consolidates the native credential-store decisions for the three
desktop platforms supported by credentials-d.

The detailed implementation contracts live in ADRs 0004-0006.

## Common rules

All native backends share these rules:

- no plaintext settings-file fallback;
- no automatic switch to another backend;
- application namespace + opaque CSPRNG locator only in routing metadata;
- no OSM username, display name, email, OAuth scope, project name, or secret
  plaintext in native metadata;
- scoped plaintext exposure through `SecretVisitor`;
- explicit non-secret status mapping;
- no native error text containing arbitrary data in the public API;
- no stronger security claim than the operating-system facility actually
  provides;
- backend availability and signing/session requirements fail closed.

## Comparison

| Property | Linux Secret Service | Windows Credential Manager | macOS Data Protection Keychain |
| --- | --- | --- | --- |
| Subpackage | `credentials-d:linux-secret-service` | `credentials-d:windows` | `credentials-d:macos-data-protection` |
| Native API | libsecret / Secret Service | WinCred | Security.framework SecItem |
| Store protection | native user credential store | native user credential store | native user credential store |
| Unlock | OS-managed/provider-managed | OS-managed | OS-managed/device lock |
| Persistence | provider-owned | local machine for same Windows user | local device |
| Mobility claim | `mayRoam` conservatively | `localDevice` | `localDevice` |
| User presence default | no | no | no |
| Blocking | may prompt | may block | may block |
| Concurrency | serialized per store | serialized per store | serialized per store |
| Binary secrets | yes, explicit length | yes, bounded blob | yes, CFData |
| Size limit | provider dependent | 2560 bytes | native framework limit |
| Metadata confidentiality | attributes are not secret | target/metadata non-secret | service/account non-secret |
| Ambiguity | exact search cardinality 0/1/>1 | random target + exact read | primary-key uniqueness |
| Synchronization | provider dependent | enterprise roaming not requested | explicitly disabled |
| Legacy fallback | none | none | none |
| Native integration gate | Ubuntu + GNOME Keyring | Windows runner | macOS runner + signed-host release gate |

## Linux

The Linux backend uses libsecret rather than implementing the Secret Service
D-Bus protocol directly.

The schema contains only:

```text
namespace
credential
```

Secret Service lookup attributes are metadata, not confidential data. The
backend therefore deliberately excludes user/profile/service identity from
attributes.

Synchronous libsecret calls may block and may request interaction. GUI consumers
must execute them away from the GUI/render thread.

Absence of a session bus or Secret Service provider returns `unavailable`.
There is no file fallback.

The generic Secret Service API does not prove local-only persistence for every
provider, so the backend conservatively reports `mayRoam`.

## Windows

The Windows backend uses the narrow WinCred API with
`CRED_TYPE_GENERIC` and requests `CRED_PERSIST_LOCAL_MACHINE`.

This means persistence for the same Windows user on the same machine. It does
not request enterprise roaming.

Generic credential blobs are limited to 2560 bytes. credentials-d validates the
limit before entering WinCred.

The backend does not claim Credential Guard or generic hardware-backed
protection.

`CredWriteW` is update-capable rather than create-only. Store therefore uses a
fresh 128-bit CSPRNG target and probes collision state first. This is not
documented as a cross-process atomic create-if-absent transaction.

Returned WinCred plaintext is overwritten before `CredFree`.

## macOS

The macOS production backend uses the Data Protection Keychain explicitly:

```text
kSecUseDataProtectionKeychain = true
kSecAttrSynchronizable        = false
kSecAttrAccessible            = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
```

It never falls back to the legacy file-based keychain.

Data Protection Keychain access depends on code signing, access groups and the
application provisioning/entitlement context. A generic command-line runner is
therefore only a fail-closed test host, not a production qualification host.

The hosted CI fixture marks that context explicitly. Security.framework may
reject different toolchain binaries at different stages; the backend itself
does not reclassify `errSecParam` as an entitlement error. A production or
normally signed integration fixture never accepts `invalidInput`.

Before credentials-d advertises the macOS backend as production-qualified, the
native integration fixture must pass in a correctly signed app-like consumer.
This requirement is tracked separately.

The default backend does not require biometrics/passcode user presence. A future
user-presence-gated policy would be a distinct reviewed backend/policy rather
than a silent behavior change.

## Residual risks

Native credential stores do not protect against every process running with the
same effective OS authority, root/administrator, a compromised desktop session,
or hostile code already executing inside the consumer process.

Provider/system backups and synchronization remain platform/provider concerns
unless the backend contract explicitly excludes them.

Logical deletion is not a claim of physical forensic erasure.

## Qualification status

- **Linux:** implemented and integration-tested against GNOME Keyring in an
  isolated D-Bus session under DMD 2.111.0 and LDC 1.41.0.
- **Windows:** implemented and native Credential Manager integration-tested
  under DMD 2.111.0 and LDC 1.41.0.
- **macOS implementation/hosted gate:** implemented and tested under LDC 1.41
  and DMD 2.113 for either full DPK operation or explicit fail-closed behavior
  in the marked unprovisioned CLI host.
- **macOS production qualification:** still requires a properly signed app-like
  consumer with real keychain-access entitlement/provisioning context.

This completes the architectural research scope of Issue #3. Platform-specific
production qualification remains an ongoing release-gate responsibility.
