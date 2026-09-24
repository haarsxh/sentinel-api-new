#!/usr/bin/env bash
# Installs the optional Hadrian engine (https://github.com/praetorian-inc/hadrian, Apache-2.0).
#
# - binary:    `go install` into $(go env GOPATH)/bin (or $GOBIN)
# - templates: fetched into ./.hadrian/src (git-ignored; Hadrian's binary does not embed them)
#
# Binary and templates are pinned to the same commit so they never drift.
set -euo pipefail

HADRIAN_REF="${HADRIAN_REF:-6a5c55e5bd41d16a1465b3ce20a3f8495fd3fafa}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SRC="$ROOT/.hadrian/src"

command -v go >/dev/null || { echo "Go 1.24+ is required: https://go.dev/dl/" >&2; exit 1; }

echo "[setup] installing hadrian@$HADRIAN_REF"
go install "github.com/praetorian-inc/hadrian/cmd/hadrian@$HADRIAN_REF"

echo "[setup] fetching templates into .hadrian/src"
if [ ! -d "$SRC/.git" ]; then
  git init -q "$SRC"
  git -C "$SRC" remote add origin https://github.com/praetorian-inc/hadrian.git
  git -C "$SRC" sparse-checkout set templates
fi
git -C "$SRC" fetch -q --depth 1 origin "$HADRIAN_REF"
git -C "$SRC" checkout -q FETCH_HEAD

BIN="$(go env GOBIN)"; BIN="${BIN:-$(go env GOPATH)/bin}"
echo "[setup] done: $BIN/hadrian, $(ls "$SRC/templates/rest" | wc -l | tr -d ' ') REST templates"
