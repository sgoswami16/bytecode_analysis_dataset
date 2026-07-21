#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
SRC="$ROOT/src"
OUT="$ROOT/out"
LIB="$ROOT/lib/hutool-all-5.7.22.jar"

mkdir -p "$OUT"

find "$SRC" -name '*.java' > "$OUT/sources.txt"
javac -encoding UTF-8 -cp "$LIB" -d "$OUT" @"$OUT/sources.txt"

echo "Build complete. Classes are in $OUT"
