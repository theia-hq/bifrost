#!/bin/sh
# fork-watch fixture: run scripts/fork-watch.sh against a throwaway repo and a fake advisory database,
# so each of its fail paths is exercised offline and a regression fails HERE instead of the watch
# passing silently in CI. Each case writes a lock and a list, then asserts the exit code plus a
# substring of the output.
# Dependency-free: POSIX sh + awk + grep + sed.

set -eu

here=$(CDPATH= cd "$(dirname "$0")" && pwd)
watch="$here/../fork-watch.sh"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

pass=0
fail=0

PIN='git+https://example.invalid/fork?rev=1111111111111111111111111111111111111111#1111111111111111111111111111111111111111'
REGISTRY='registry+https://github.com/rust-lang/crates.io-index'

# The fake database: two advisories against the upstream, none against anything else.
mkdir -p "$tmp/db/crates/upstream"
: > "$tmp/db/crates/upstream/RUSTSEC-0000-0001.md"
: > "$tmp/db/crates/upstream/RUSTSEC-0000-0002.md"

# A lock holding `fork` from the given source.
lock() {
  printf '[[package]]\nname = "fork"\nversion = "1.0.0"\nsource = "%s"\n' "$1" > "$tmp/repo/Cargo.lock"
}

# A list made of the given rows.
list() {
  printf '%s\n' "$@" > "$tmp/repo/scripts/fork-watch.txt"
}

# case <name> <expected exit> <expected output substring>
case_() {
  name=$1 want=$2 needle=$3
  set +e
  out=$(ADVISORY_DB="$tmp/db" sh "$watch" "$tmp/repo" 2>&1)
  got=$?
  set -e
  if [ "$got" -eq "$want" ] && printf '%s' "$out" | grep -qF -- "$needle"; then
    pass=$((pass + 1))
  else
    echo "FAIL $name: exit $got (want $want), output:" >&2
    printf '%s\n' "$out" >&2
    fail=$((fail + 1))
  fi
}

mkdir -p "$tmp/repo/scripts"

lock "$PIN"
list "# a comment" "fork upstream RUSTSEC-0000-0001 ported" "fork upstream RUSTSEC-0000-0002 pinned $PIN"
case_ "every advisory has a row and the pin holds" 0 "fork-watch: OK"

list "fork upstream RUSTSEC-0000-0001 ported"
case_ "an advisory with no row" 1 "RUSTSEC-0000-0002 is filed against upstream and fork has no row"

lock "$REGISTRY"
list "fork upstream RUSTSEC-0000-0001 ported" "fork upstream RUSTSEC-0000-0002 pinned $PIN"
case_ "the patch was dropped" 1 "fork resolves from $REGISTRY, but RUSTSEC-0000-0002 is pinned"

lock "$REGISTRY"
list "fork upstream RUSTSEC-0000-0001 ported" "fork upstream RUSTSEC-0000-0002 ported" "gone elsewhere -"
case_ "a listed fork not in the lock" 1 "gone is listed but not in Cargo.lock"

list "fork upstream RUSTSEC-0000-0001 ported" "fork upstream RUSTSEC-0000-0002 maybe"
case_ "a malformed row" 1 "is malformed"

list "fork upstream RUSTSEC-0000-0001 ported" "fork upstream RUSTSEC-0000-0002 pinned"
case_ "a pin with no source" 1 "is malformed"

echo "fork-watch fixture: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
