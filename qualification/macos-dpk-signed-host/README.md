# macOS Data Protection Keychain signed-host qualification

This fixture continues issue #22.

Apple's Data Protection Keychain on macOS uses the iOS-style keychain access
group model. The effective groups are derived from code-signing entitlements,
and restricted entitlement claims must be authorized by a provisioning
profile.

A generic command-line binary or an ad-hoc signature is therefore useful only
as a fail-closed negative control. It is not production qualification.

## What this fixture does

The runner:

1. builds the existing native DPK integration executable;
2. embeds it in a minimal macOS `.app` bundle;
3. embeds the supplied provisioning profile;
4. decodes the profile and verifies that it authorizes the selected bundle
   identifier and corresponding keychain access group;
5. generates the minimal concrete entitlements:
   - `com.apple.application-identifier`;
   - `com.apple.developer.team-identifier`;
   - `keychain-access-groups`;
6. signs the bundle with the supplied code-signing identity;
7. verifies the signature;
8. prints the effective code-signing entitlements;
9. runs the existing Data Protection Keychain contract in
   `CREDENTIALS_D_MACOS_REQUIRE_FULL=1` mode.

Strict mode does not accept `permissionDenied`, `unavailable`, or
`invalidInput` as a hosted-runner exception.

A full PASS exercises:

- binary secret with embedded NUL;
- store/read;
- reopen through a fresh backend instance;
- replace;
- wrong namespace rejection;
- delete/notFound;
- Data Protection Keychain only;
- `synchronizable=false`;
- `WhenUnlockedThisDeviceOnly`;
- no legacy keychain fallback.

## Local production run

The Mac must have a suitable signing certificate in its keychain and a
provisioning profile that authorizes the bundle identifier/keychain group.

```bash
export DC=ldc2
export CREDENTIALS_D_MACOS_BUNDLE_ID="org.example.credentials-d-qualification"
export CREDENTIALS_D_MACOS_SIGNING_IDENTITY="Apple Development: Example (TEAMID)"
export CREDENTIALS_D_MACOS_PROVISIONING_PROFILE="$HOME/path/profile.provisionprofile"

bash qualification/macos-dpk-signed-host/run.sh
```

Repeat with the second supported compiler where practical.

Receipts are written to:

```text
qualification-results/macos-dpk/
```

The directory is ignored by Git.

## Hosted ad-hoc negative control

The repository's normal macOS platform gate runs:

```bash
bash qualification/macos-dpk-signed-host/run.sh --adhoc
```

This proves that the same app-bundle fixture remains fail-closed when the
restricted entitlement/provisioning context is absent.

An ad-hoc PASS must never be interpreted as production DPK qualification.

## GitHub production workflow

`.github/workflows/macos-dpk-production-qualification.yml` is manual-only.

It requires these repository secrets:

- `MACOS_QUALIFICATION_CERTIFICATE_P12_BASE64`
- `MACOS_QUALIFICATION_CERTIFICATE_PASSWORD`
- `MACOS_QUALIFICATION_PROVISIONING_PROFILE_BASE64`

The workflow imports the certificate into a temporary keychain, decodes the
profile into a temporary file, discovers the imported signing identity, runs
the strict signed-host fixture for both configured D toolchains, uploads only
the generated qualification receipts, and destroys the temporary keychain at
job end.

Do not print or upload the P12, its password, or the provisioning profile.

## Completion rule

Issue #22 can be closed only after a strict provisioned-host receipt shows
`result=PROVISIONED_FULL_PASS` in a normal logged-in macOS user session for
the actual signing/provisioning model intended for production.

The ad-hoc hosted-runner result is a regression/negative-control gate only.
