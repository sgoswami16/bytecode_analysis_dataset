#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
DATASET="$ROOT/Solidity bytecode dataset"
OUTPUT="$ROOT/obfucsacion/output/batch"

if [[ ! -d "$DATASET" ]]; then
  echo "Dataset directory not found: $DATASET"
  exit 1
fi

mkdir -p "$OUTPUT"
"$ROOT/obfucsacion/build.sh" >/dev/null

count=0
failed=0

for input in "$DATASET"/*.hex; do
  [[ -e "$input" ]] || continue
  name="$(basename "$input")"
  echo "[$((count + 1))] Obfuscating $name"
  if "$ROOT/obfuscate.sh" "$input" "$OUTPUT"; then
    count=$((count + 1))
  else
    failed=$((failed + 1))
    echo "Failed: $name" >&2
  fi
done

echo "Done. Processed $count file(s), $failed failure(s). Output: $OUTPUT"
