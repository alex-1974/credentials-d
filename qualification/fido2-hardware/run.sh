#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
RESULT_DIR="$ROOT/qualification-results/fido2"
mkdir -p "$RESULT_DIR"

COMPILER="${DC:-dmd}"
COMPILER_TAG="$(basename "$COMPILER" | tr -c 'A-Za-z0-9._-' '_')"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
RECEIPT="$RESULT_DIR/${STAMP}-${COMPILER_TAG}.txt"

DISCOVER_ONLY=0
for arg in "$@"; do
  if [[ "$arg" == "--discover-only" ]]; then
    DISCOVER_ONLY=1
    break
  fi
done

restore_tty() {
  if [[ -t 0 ]]; then
    stty echo 2>/dev/null || true
  fi
}

# A PIN may be required even for the user-presence policy on PIN-protected
# CTAP2.0 authenticators during MakeCredential. Disable terminal echo for every
# interactive qualification run, not only for --uv.
if [[ "$DISCOVER_ONLY" == "0" && -t 0 ]]; then
  trap restore_tty EXIT INT TERM
  stty -echo
fi

{
  echo "receipt=fido2-hardware-qualification-v1"
  echo "timestamp_utc=$STAMP"
  echo "git_commit=$(git -C "$ROOT" rev-parse HEAD)"
  echo "kernel=$(uname -srmo)"
  echo "compiler_command=$COMPILER"
  "$COMPILER" --version | head -n 1
  dub --version
  pkg-config --modversion libfido2
  pkg-config --modversion libsodium
  echo "--- qualification runner ---"

  dub run \
    --root="$ROOT/qualification/fido2-hardware" \
    --compiler="$COMPILER" \
    --force \
    -- "$@"
} 2>&1 | tee "$RECEIPT"

restore_tty
trap - EXIT INT TERM

echo
echo "Receipt: $RECEIPT"
