#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
OUT="$ROOT/out"
LIB="$ROOT/lib/hutool-all-5.7.22.jar"

if [[ ! -f "$OUT/Main.class" ]]; then
  "$ROOT/build.sh"
fi

mkdir -p "$ROOT/output"
cd "$ROOT"
java -cp "$OUT:$LIB" Main "$@"
