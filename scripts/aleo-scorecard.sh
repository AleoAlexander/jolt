#!/usr/bin/env bash
# Records an aleo-transfer benchmark run into examples/aleo-transfer/RESULTS.md.
# Usage: ./scripts/aleo-scorecard.sh <label>
#   FEATURES=guest/field-inline ./scripts/aleo-scorecard.sh <label>   # optional guest features
set -euo pipefail
LABEL="${1:?usage: aleo-scorecard.sh <label>}"
cd "$(dirname "$0")/.."
export CARGO_PROFILE_RELEASE_LTO=off

cargo build --release -q --bin jolt
cargo build --release -q -p aleo-transfer ${FEATURES:+--features "$FEATURES"}

OUT=$(PATH="$PWD/target/release:$PATH" /usr/bin/time -l ./target/release/aleo-transfer 2>&1)

{
  echo "## ${LABEL} — $(date +%Y-%m-%d) — $(git rev-parse --short HEAD)${FEATURES:+ — features: $FEATURES}"
  echo '```'
  echo "$OUT" | grep -E 'total cycles|trace length|prover time|proof size|verify time|maximum resident' \
    | sed -E 's/^[[:space:]]*//; s/\x1b\[[0-9;]*m//g' | sed -E 's/^[0-9TZ:.-]+ +INFO +trace: tracer::emulator::cpu: //'
  echo '```'
  echo
} >> examples/aleo-transfer/RESULTS.md
echo "recorded: ${LABEL}"
