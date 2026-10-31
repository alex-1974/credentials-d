#!/usr/bin/env bash

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
RESULT_DIR="$ROOT/qualification-results/fido2"
mkdir -p "$RESULT_DIR" || {
  echo "Failed to create qualification result directory." >&2
  return 2 2>/dev/null || true
}

COMPILER="${DC:-dmd}"
COMPILER_TAG="$(basename "$COMPILER" | tr -c 'A-Za-z0-9._-' '_')"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
RECEIPT="$RESULT_DIR/${STAMP}-${COMPILER_TAG}.txt"
QUAL_ROOT="$ROOT/qualification/fido2-hardware"
BINARY="$QUAL_ROOT/credentials-d-fido2-hardware-qualification"

DISCOVER_ONLY=0
HAS_WORK_DIR=0
for arg in "$@"; do
  if [[ "$arg" == "--discover-only" ]]; then
    DISCOVER_ONLY=1
  elif [[ "$arg" == "--work-dir" ]]; then
    HAS_WORK_DIR=1
  fi
done

AUTO_WORK_DIR=""
RUNNER_ARGS=("$@")

if [[ "$DISCOVER_ONLY" == "0" && "$HAS_WORK_DIR" == "0" ]]; then
  AUTO_WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/credentials-d-fido2-qualification.XXXXXX")" || {
    echo "Failed to create private qualification work directory." >&2
    return 2 2>/dev/null || true
  }
  chmod 700 "$AUTO_WORK_DIR" || {
    rm -rf -- "$AUTO_WORK_DIR"
    echo "Failed to secure qualification work directory." >&2
    return 2 2>/dev/null || true
  }
  RUNNER_ARGS+=(--work-dir "$AUTO_WORK_DIR")
fi

restore_tty() {
  if [[ -t 0 ]]; then
    stty echo 2>/dev/null || true
  fi
}

cleanup() {
  restore_tty
  if [[ -n "$AUTO_WORK_DIR" ]]; then
    rm -rf -- "$AUTO_WORK_DIR"
  fi
}

if [[ "$DISCOVER_ONLY" == "0" && -t 0 ]]; then
  trap cleanup EXIT INT TERM
  stty -echo
elif [[ "$DISCOVER_ONLY" == "0" ]]; then
  trap cleanup EXIT INT TERM
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
  echo "--- qualification build ---"
} 2>&1 | tee "$RECEIPT"

dub build \
  --root="$QUAL_ROOT" \
  --compiler="$COMPILER" \
  --force 2>&1 | tee -a "$RECEIPT"
BUILD_STATUS=${PIPESTATUS[0]}

if [[ "$BUILD_STATUS" -ne 0 ]]; then
  cleanup
  trap - EXIT INT TERM
  {
    echo "build_exit_code=$BUILD_STATUS"
    echo "result=BUILD_FAILED"
  } | tee -a "$RECEIPT"
  return "$BUILD_STATUS" 2>/dev/null || true
fi

{
  echo "--- qualification runner ---"
  echo "binary=$BINARY"
} | tee -a "$RECEIPT"

"$BINARY" "${RUNNER_ARGS[@]}" 2>&1 | tee -a "$RECEIPT"
PROGRAM_STATUS=${PIPESTATUS[0]}

cleanup
trap - EXIT INT TERM

{
  echo "program_exit_code=$PROGRAM_STATUS"
  if [[ "$PROGRAM_STATUS" -ge 128 ]]; then
    echo "program_signal=$((PROGRAM_STATUS - 128))"
  fi
  echo "Receipt: $RECEIPT"
} | tee -a "$RECEIPT"

if [[ "$PROGRAM_STATUS" -ne 0 ]]; then
  return "$PROGRAM_STATUS" 2>/dev/null || true
fi
