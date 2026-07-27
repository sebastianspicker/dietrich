#!/usr/bin/env bash
# Run the documented commands against examples/out samples.
# Usage (repo root):
#   pip install -e '.[full]'
#   python examples/generate_samples.py
#   bash examples/run_demos.sh
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$ROOT/examples/out"
cd "$ROOT"

if [[ ! -f "$OUT/protected.xlsx" ]]; then
  echo "samples missing - run: python examples/generate_samples.py" >&2
  exit 1
fi

run() {
  echo
  echo "\$ $*"
  "$@"
}

echo "=== Dietrich example demos ==="

run python -m dietrich --help | head -20

run python -m dietrich "$OUT/protected.xlsx" --inspect
run python -m dietrich "$OUT/protected.xlsx" --output "$OUT/protected_unlocked.xlsx" --force
run python -m dietrich "$OUT/protected.docx" --output "$OUT/protected_unlocked.docx" --force
run python -m dietrich "$OUT/protected.pptx" --output "$OUT/protected_unlocked.pptx" --force

if [[ -f "$OUT/plain.xls" ]]; then
  run python -m dietrich "$OUT/plain.xls" --output "$OUT/plain_unlocked.xls" --force
fi

if [[ -f "$OUT/encrypted.xlsx" ]]; then
  run python -m dietrich "$OUT/encrypted.xlsx" --inspect
  run python -m dietrich "$OUT/encrypted.xlsx" --export-hash hashcat | head -c 120
  echo "…"
  run python -m dietrich "$OUT/encrypted.xlsx" --password 'Password1234_' \
    --output "$OUT/encrypted_unlocked.xlsx" --force
  # honest soft-only failure
  set +e
  run python -m dietrich "$OUT/encrypted.xlsx" --soft-only --output "$OUT/should_fail.xlsx"
  set -e
fi

if [[ -f "$OUT/restricted.pdf" ]]; then
  run python -m dietrich "$OUT/restricted.pdf" --output "$OUT/restricted_unlocked.pdf" --force
fi

if [[ -f "$OUT/user_locked.pdf" ]]; then
  run python -m dietrich "$OUT/user_locked.pdf" --password demo \
    --output "$OUT/user_locked_unlocked.pdf" --force
fi

if [[ -f "$OUT/signed.xlsx" ]]; then
  set +e
  run python -m dietrich "$OUT/signed.xlsx" --output "$OUT/signed_blocked.xlsx"
  set -e
  run python -m dietrich "$OUT/signed.xlsx" --strip-signatures \
    --output "$OUT/signed_unsigned.xlsx" --force
fi

run python -m dietrich "$OUT/protected.xlsx" --inspect --json | head -20

echo
echo "=== demos finished (outputs under examples/out/) ==="
