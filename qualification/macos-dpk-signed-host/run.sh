#!/usr/bin/env bash
set -euo pipefail

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "macOS signed-host qualification requires Darwin." >&2
  exit 2
fi

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
COMPILER="${DC:-dmd}"
BUNDLE_ID="${CREDENTIALS_D_MACOS_BUNDLE_ID:-org.alex1974.credentials-d-qualification}"
SIGNING_IDENTITY="${CREDENTIALS_D_MACOS_SIGNING_IDENTITY:-}"
PROFILE="${CREDENTIALS_D_MACOS_PROVISIONING_PROFILE:-}"
ADHOC=0

if [[ "${1:-}" == "--adhoc" ]]; then
  ADHOC=1
fi

STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
COMPILER_TAG="$(basename "$COMPILER" | tr -c 'A-Za-z0-9._-' '_')"
MODE="provisioned"
if [[ "$ADHOC" == "1" ]]; then
  MODE="adhoc-negative-control"
fi

RESULT_DIR="$ROOT/qualification-results/macos-dpk"
mkdir -p "$RESULT_DIR"
RECEIPT="$RESULT_DIR/${STAMP}-${COMPILER_TAG}-${MODE}.txt"

WORK_ROOT="${RUNNER_TEMP:-/tmp}"
WORK="$(mktemp -d "$WORK_ROOT/credentials-d-macos-dpk.XXXXXX")"
APP="$WORK/CredentialsDKeychainQualification.app"
CONTENTS="$APP/Contents"
MACOS="$CONTENTS/MacOS"
EXECUTABLE_NAME="credentials-d-macos-data-protection-integration"
EXECUTABLE="$MACOS/$EXECUTABLE_NAME"
PROFILE_PLIST="$WORK/profile.plist"
ENTITLEMENTS="$WORK/qualification.entitlements"

cleanup() {
  rm -rf "$WORK"
}
trap cleanup EXIT

mkdir -p "$MACOS"

dub build \
  --root="$ROOT/tests/macos-data-protection-integration" \
  --compiler="$COMPILER" \
  --force

cp \
  "$ROOT/tests/macos-data-protection-integration/$EXECUTABLE_NAME" \
  "$EXECUTABLE"

cat > "$CONTENTS/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleDevelopmentRegion</key>
    <string>en</string>
    <key>CFBundleExecutable</key>
    <string>$EXECUTABLE_NAME</string>
    <key>CFBundleIdentifier</key>
    <string>$BUNDLE_ID</string>
    <key>CFBundleName</key>
    <string>CredentialsDKeychainQualification</string>
    <key>CFBundlePackageType</key>
    <string>APPL</string>
    <key>CFBundleShortVersionString</key>
    <string>1.0</string>
    <key>CFBundleVersion</key>
    <string>1</string>
    <key>LSBackgroundOnly</key>
    <true/>
</dict>
</plist>
PLIST

if [[ "$ADHOC" == "1" ]]; then
  codesign \
    --force \
    --sign - \
    --timestamp=none \
    "$APP"
else
  if [[ -z "$SIGNING_IDENTITY" ]]; then
    echo "CREDENTIALS_D_MACOS_SIGNING_IDENTITY is required." >&2
    exit 2
  fi

  if [[ -z "$PROFILE" || ! -f "$PROFILE" ]]; then
    echo "CREDENTIALS_D_MACOS_PROVISIONING_PROFILE must name a readable profile." >&2
    exit 2
  fi

  security cms -D -i "$PROFILE" > "$PROFILE_PLIST"

  BUNDLE_ID="$BUNDLE_ID" PROFILE_PLIST="$PROFILE_PLIST" ENTITLEMENTS="$ENTITLEMENTS" \
    python3 <<'PY'
import os
import plistlib
import sys

bundle_id = os.environ["BUNDLE_ID"]
profile_path = os.environ["PROFILE_PLIST"]
entitlements_path = os.environ["ENTITLEMENTS"]

with open(profile_path, "rb") as f:
    profile = plistlib.load(f)

prefixes = profile.get("ApplicationIdentifierPrefix") or []
teams = profile.get("TeamIdentifier") or []
profile_entitlements = profile.get("Entitlements") or {}

if not prefixes or not teams:
    raise SystemExit("provisioning profile lacks application prefix/team identifier")

prefix = prefixes[0]
team = teams[0]
app_identifier = f"{prefix}.{bundle_id}"

profile_app_identifier = (
    profile_entitlements.get("com.apple.application-identifier")
    or profile_entitlements.get("application-identifier")
)

def permits(pattern, value):
    if not isinstance(pattern, str):
        return False
    if pattern.endswith("*"):
        return value.startswith(pattern[:-1])
    return pattern == value

if not permits(profile_app_identifier, app_identifier):
    raise SystemExit(
        f"profile application identifier {profile_app_identifier!r} "
        f"does not authorize {app_identifier!r}"
    )

groups = profile_entitlements.get("keychain-access-groups") or []
if not any(permits(group, app_identifier) for group in groups):
    raise SystemExit(
        "provisioning profile does not authorize the qualification "
        "application identifier as a keychain access group"
    )

entitlements = {
    "com.apple.application-identifier": app_identifier,
    "com.apple.developer.team-identifier": team,
    "keychain-access-groups": [app_identifier],
}

with open(entitlements_path, "wb") as f:
    plistlib.dump(entitlements, f, sort_keys=True)

print(f"profile_team_identifier={team}")
print(f"profile_application_identifier={profile_app_identifier}")
print(f"qualification_application_identifier={app_identifier}")
print(f"qualification_keychain_access_group={app_identifier}")
PY

  cp "$PROFILE" "$CONTENTS/embedded.provisionprofile"

  codesign \
    --force \
    --sign "$SIGNING_IDENTITY" \
    --entitlements "$ENTITLEMENTS" \
    --timestamp=none \
    "$APP"
fi

{
  echo "receipt=macos-dpk-signed-host-v1"
  echo "timestamp_utc=$STAMP"
  echo "mode=$MODE"
  echo "git_commit=$(git -C "$ROOT" rev-parse HEAD)"
  echo "bundle_id=$BUNDLE_ID"
  echo "compiler_command=$COMPILER"
  "$COMPILER" --version | head -n 1
  dub --version
  sw_vers

  echo "--- codesign verify ---"
  codesign --verify --deep --strict --verbose=4 "$APP"

  echo "--- codesign identity ---"
  codesign -dv --verbose=4 "$APP" 2>&1

  echo "--- effective entitlements ---"
  codesign -d --entitlements :- "$APP" 2>&1

  echo "--- Data Protection Keychain integration ---"
  if [[ "$ADHOC" == "1" ]]; then
    CREDENTIALS_D_MACOS_UNPROVISIONED_CI=1 \
      "$EXECUTABLE"
    echo "result=ADHOC_NEGATIVE_CONTROL_PASS"
  else
    CREDENTIALS_D_MACOS_REQUIRE_FULL=1 \
      "$EXECUTABLE"
    echo "result=PROVISIONED_FULL_PASS"
  fi
} 2>&1 | tee "$RECEIPT"

echo
echo "Receipt: $RECEIPT"
