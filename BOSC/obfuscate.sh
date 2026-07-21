#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
OBF="$ROOT/obfucsacion"

if [[ $# -lt 1 ]]; then
  echo "Usage: $0 <input.hex> [output-dir] [--entire]"
  echo
  echo "Examples:"
  echo "  $0 obfucsacion/src/dataset/example.hex"
  echo "  $0 \"Solidity bytecode dataset/0xa3f7871a4b86bcc3b6e97c8fd0745e71c55e1f82.hex\""
  exit 1
fi

INPUT="$1"
if [[ ! "$INPUT" = /* ]]; then
  INPUT="$ROOT/$INPUT"
fi

shift
"$OBF/run.sh" "$INPUT" "$@"
