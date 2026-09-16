#!/bin/sh
# sealed-gate fixture: exercise the PASS and FAIL paths of scripts/sealed-gate.sh on throwaway trees,
# so a regression in the comment filter, the per-hit profile match, the profile table, or the
# `[package]` name parse fails HERE instead of passing silently in CI (delib-72; the Rust Reviewer's
# D5, MAJOR-1; the Adversary's P-1). Every case builds a temp tree with a `[package]` manifest and a
# `src/lib.rs`, runs the gate against it, and asserts the exit code plus a substring of the output.
# Dependency-free: POSIX sh + find + grep + sed.

set -eu

here=$(CDPATH= cd "$(dirname "$0")" && pwd)
gate="$here/../sealed-gate.sh"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

pass=0
fail=0

# write_crate <case> <crate> <lib.rs line>: a throwaway crate tree with a plain `[package]` manifest.
write_crate() {
  dir="$tmp/$1/$2"
  mkdir -p "$dir/src"
  cat > "$dir/Cargo.toml" <<EOF
[package]
name = "$2"
version = "0.0.0"
edition = "2024"
EOF
  printf '%s\n' "$3" > "$dir/src/lib.rs"
}

# write_spoof_crate <case> <crate> <spoofed name> <lib.rs line>: a manifest whose FIRST `name =` line
# sits outside `[package]`, so only a `[package]`-scoped parse reads the real crate name.
write_spoof_crate() {
  dir="$tmp/$1/$2"
  mkdir -p "$dir/src"
  cat > "$dir/Cargo.toml" <<EOF
[lib]
name = "$3"

[package]
name = "$2"
version = "0.0.0"
edition = "2024"
EOF
  printf '%s\n' "$4" > "$dir/src/lib.rs"
}

# write_quoted_crate <case> <crate> <lib.rs line>: a manifest whose `[package]` name is a TOML
# literal (single-quoted) string, so the gate's name parse cannot read it; the gate must fail loud
# instead of skipping the crate (the Adversary's P-1).
write_quoted_crate() {
  dir="$tmp/$1/$2"
  mkdir -p "$dir/src"
  cat > "$dir/Cargo.toml" <<EOF
[package]
name = '$2'
version = "0.0.0"
edition = "2024"
EOF
  printf '%s\n' "$3" > "$dir/src/lib.rs"
}

# expect_ok <label> <root> [needle]: the gate exits 0 (and the output carries `needle` when given).
expect_ok() {
  label=$1
  root=$2
  needle=${3:-}
  if out=$(sh "$gate" "$root" 2>&1); then
    if [ -z "$needle" ] || printf '%s\n' "$out" | grep -q -- "$needle"; then
      pass=$((pass + 1))
      printf 'ok   %s\n' "$label"
    else
      fail=$((fail + 1))
      printf 'FAIL %s: the output does not mention "%s"\n%s\n' "$label" "$needle" "$out"
    fi
  else
    fail=$((fail + 1))
    printf 'FAIL %s: the gate exited non-zero\n%s\n' "$label" "$out"
  fi
}

# expect_fail <label> <root> <needle>: the gate exits non-zero and names the refusal.
expect_fail() {
  label=$1
  root=$2
  needle=$3
  if out=$(sh "$gate" "$root" 2>&1); then
    fail=$((fail + 1))
    printf 'FAIL %s: the gate exited zero\n%s\n' "$label" "$out"
  elif printf '%s\n' "$out" | grep -q -- "$needle"; then
    pass=$((pass + 1))
    printf 'ok   %s\n' "$label"
  else
    fail=$((fail + 1))
    printf 'FAIL %s: the output does not mention "%s"\n%s\n' "$label" "$needle" "$out"
  fi
}

# The fail path: an unreviewed crate may not declare either proof-bearing spelling.
write_crate unreviewed-sealed liar1 'pub struct X; impl X { type Security = Sealed; }'
expect_fail 'unreviewed Sealed fails' "$tmp/unreviewed-sealed" 'not reviewed'

write_crate unreviewed-inprocess liar2 'pub struct X; impl X { type Security = InProcess; }'
expect_fail 'unreviewed InProcess fails' "$tmp/unreviewed-inprocess" 'not reviewed'

# The pass path: a table crate declaring exactly its reviewed profile.
write_crate reviewed-sealed bifrost-iroh 'pub struct X; impl X { type Security = Sealed; }'
expect_ok 'reviewed Sealed passes' "$tmp/reviewed-sealed" '1 reviewed profile declaration'

write_crate reviewed-inprocess bifrost-mem 'pub struct X; impl X { type Security = InProcess; }'
expect_ok 'reviewed InProcess passes' "$tmp/reviewed-inprocess" '1 reviewed profile declaration'

# A table crate may not declare the OTHER proof-bearing spelling.
write_crate wrong-profile bifrost-mem 'pub struct X; impl X { type Security = Sealed; }'
expect_fail 'a profile outside the crate pair fails' "$tmp/wrong-profile" 'not reviewed'

# MAJOR-1: the profile match is per hit, on the declaration token, so a trailing mention of the
# crate's ALLOWED profile cannot mask the other proof-bearing declaration, in either direction.
write_crate masked-sealed bifrost-mem 'pub struct X; impl X { type Security = Sealed; } // audit note: type Security = InProcess is not used'
expect_fail 'a trailing InProcess mention does not mask a Sealed declaration' "$tmp/masked-sealed" 'not reviewed'

write_crate masked-inprocess bifrost-iroh 'pub struct X; impl X { type Security = InProcess; } // audit: type Security = Sealed reviewed'
expect_fail 'a trailing Sealed mention does not mask an InProcess declaration' "$tmp/masked-inprocess" 'not reviewed'

# `Announced` is free, and an unknown token is not a Sealed match.
write_crate announced-free liar3 'pub struct X; impl X { type Security = Announced; }'
expect_ok 'Announced is free' "$tmp/announced-free"

write_crate extended-token liar4 'pub struct X; impl X { type Security = SealedExt; }'
expect_ok 'an unknown profile token is not a match' "$tmp/extended-token"

# The comment filter: a comment-leading mention passes; a trailing citation cannot suppress a hit.
write_crate comment-mention liar5 '// type Security = Sealed;'
expect_ok 'a comment-leading mention passes' "$tmp/comment-mention"

write_crate trailing-url liar6 'pub struct X; impl X { type Security = Sealed; } // audited: https://example.com/review'
expect_fail 'a trailing URL cannot suppress a hit' "$tmp/trailing-url" 'not reviewed'

# The escape hatch: a marker WITH a review ref passes and is counted; a bare marker is not an escape.
write_crate cited-exception liar7 'pub struct X; impl X { type Security = Sealed; } // sealed-gate:allow notes/reviews/example.md'
expect_ok 'a cited exception passes and is counted' "$tmp/cited-exception" '1 cited exception'

write_crate bare-marker liar8 'pub struct X; impl X { type Security = Sealed; } // sealed-gate:allow'
expect_fail 'a bare marker is not an escape' "$tmp/bare-marker" 'not reviewed'

# The `[package]`-only parse: a first `name =` outside `[package]` must not spoof a table entry.
write_spoof_crate spoof namespoof-liar bifrost-iroh 'pub struct X; impl X { type Security = Sealed; }'
expect_fail 'a manifest-name spoof does not ride a table entry' "$tmp/spoof" 'not reviewed'

# The `[package]` parse: a name the gate cannot read fails loud instead of hiding the crate (P-1).
write_quoted_crate quoted-name liar9 'pub struct X; impl X { type Security = Sealed; }'
expect_fail 'a single-quoted package name fails loud' "$tmp/quoted-name" 'UNPARSED'

# An empty tree (no manifests) passes.
mkdir -p "$tmp/empty"
expect_ok 'an empty tree passes' "$tmp/empty"

printf '\nsealed-gate fixture: %s passed, %s failed.\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
