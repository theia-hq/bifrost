#!/bin/sh
# sealed-gate fixture: exercise every PASS and FAIL path of scripts/sealed-gate.sh on throwaway trees,
# so a regression in the impl pattern, the comment filter, the `[package]` name parse, the transport
# list, the test-only rule, or the required-case check fails HERE instead of passing silently in CI.
# Each case builds a temp tree, runs the gate against it, and asserts the exit code plus a substring
# of the output. Dependency-free: POSIX sh + find + grep + sed.

set -eu

here=$(CDPATH= cd "$(dirname "$0")" && pwd)
gate="$here/../sealed-gate.sh"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

pass=0
fail=0

# write_crate <case> <crate> <lib.rs text>: a throwaway crate with a plain `[package]` manifest.
write_crate() {
  dir="$tmp/$1/$2"
  mkdir -p "$dir/src"
  printf '[package]\nname = "%s"\nversion = "0.0.0"\nedition = "2024"\n' "$2" > "$dir/Cargo.toml"
  printf '%s\n' "$3" > "$dir/src/lib.rs"
}

# write_manifest <case> <crate> <manifest text>: a crate whose manifest is given whole, with an
# unlisted impl in its source, so the gate's verdict turns on the name it reads.
write_manifest() {
  dir="$tmp/$1/$2"
  mkdir -p "$dir/src"
  printf '%s\n' "$3" > "$dir/Cargo.toml"
  printf 'pub struct X;\nimpl Transport for X {}\n' > "$dir/src/lib.rs"
}

# write_suite <case> <tests/x.rs text>: a crate that takes the test-only backend as a dev-dependency
# and carries one integration test file.
write_suite() {
  dir="$tmp/$1/suite"
  mkdir -p "$dir/src" "$dir/tests"
  printf '[package]\nname = "suite"\nversion = "0.0.0"\n\n[dev-dependencies]\nbifrost-mem = { path = "../bifrost-mem" }\n' > "$dir/Cargo.toml"
  : > "$dir/src/lib.rs"
  printf '%s\n' "$2" > "$dir/tests/x.rs"
}

# expect_ok <label> <case> [needle]: the gate exits 0 (and the output carries `needle` when given).
expect_ok() {
  if out=$(sh "$gate" "$tmp/$2" 2>&1); then
    if [ -z "${3:-}" ] || printf '%s\n' "$out" | grep -q -- "$3"; then
      pass=$((pass + 1))
      printf 'ok   %s\n' "$1"
      return
    fi
  fi
  fail=$((fail + 1))
  printf 'FAIL %s\n%s\n' "$1" "$out"
}

# expect_fail <label> <case> <needle>: the gate exits non-zero and the output names the refusal.
expect_fail() {
  if out=$(sh "$gate" "$tmp/$2" 2>&1); then
    :
  elif printf '%s\n' "$out" | grep -q -- "$3"; then
    pass=$((pass + 1))
    printf 'ok   %s\n' "$1"
    return
  fi
  fail=$((fail + 1))
  printf 'FAIL %s\n%s\n' "$1" "$out"
}

every_case='use bifrost_iroh::Endpoint;
fn t() { identity_binding(a, b); wrong_key_rejected(a, b, c); an_aborted_writer_errors_the_peers_read(a, b); }'

# The pass path: both listed crates implement both traits, the backend runs the required cases, and
# the test-only backend is taken as a dev-dependency.
write_crate listed bifrost-iroh 'impl Transport for E {}
impl Session for S {}'
write_crate listed bifrost-mem 'impl Transport for M {}
impl Session for N {}'
write_suite listed "$every_case"
expect_ok 'listed crates pass' listed '4 Transport/Session impl'

# The list: any other crate's impl fails.
write_crate unlisted liar 'impl Transport for X {}'
expect_fail 'an unlisted crate fails' unlisted 'UNLISTED'

# The `[package]`-only name parse: a first `name =` outside `[package]` does not ride a list entry.
write_manifest spoof liar '[lib]
name = "bifrost-mem"

[package]
name = "liar"'
expect_fail 'a [lib] name does not spoof a listed crate' spoof 'UNLISTED    crate liar'

# A name the parse cannot read fails loud instead of hiding the crate.
write_manifest unparsed liar "[package]
name = 'liar'"
expect_fail 'a single-quoted package name fails loud' unparsed 'UNPARSED'

# The comment filter: a comment-leading mention passes; a trailing comment does not hide an impl.
write_crate comment liar '/// impl Transport for X {}
// impl Session for X {}'
expect_ok 'a comment-leading mention passes' comment

write_crate trailing liar 'impl Transport for X {} // reviewed elsewhere'
expect_fail 'a trailing comment does not hide an impl' trailing 'UNLISTED'

# The word boundary: a longer trait name is not a match.
write_crate boundary liar 'impl SubTransport for X {}
impl TransportExt for X {}
impl SessionStore for X {}'
expect_ok 'SubTransport, TransportExt and SessionStore pass' boundary

# The spellings: raw, macro path, absolute path, split header, and the Session trait.
write_crate raw liar 'impl r#Transport for X {}'
expect_fail 'impl r#Transport fails' raw 'UNLISTED'

write_crate macro-path liar 'impl $crate::Transport for X {}'
expect_fail 'impl $crate::Transport fails' macro-path 'UNLISTED'

write_crate absolute liar 'impl ::bifrost_transport::Transport for X {}'
expect_fail 'impl ::path::Transport fails' absolute 'UNLISTED'

write_crate split liar 'impl<D: Discovery + Send + Sync + '"'"'static> Transport
    for Wrapped<D> {}'
expect_fail 'a rustfmt-split Transport header fails' split 'UNLISTED'

write_crate session liar 'impl Session for X {}'
expect_fail 'impl Session fails' session 'UNLISTED'

write_crate split-session liar 'impl<T: Session + Send + Sync + '"'"'static> Session
    for Wrapped<T> {}'
expect_fail 'a rustfmt-split Session header fails' split-session 'UNLISTED'

# The required cases: a listed backend with no test file running every one fails, and a subset is not
# enough.
write_crate no-cases bifrost-iroh 'impl Transport for E {}'
expect_fail 'a backend with no required cases fails' no-cases 'NO-CASES'

write_crate half-identity bifrost-iroh 'impl Transport for E {}'
write_suite half-identity 'use bifrost_iroh::Endpoint;
fn t() { identity_binding(a, b); an_aborted_writer_errors_the_peers_read(a, b); }'
expect_fail 'a backend running one identity case fails' half-identity 'NO-CASES'

write_crate no-abort bifrost-iroh 'impl Transport for E {}'
write_suite no-abort 'use bifrost_iroh::Endpoint;
fn t() { identity_binding(a, b); wrong_key_rejected(a, b, c); }'
expect_fail 'a backend running no abort case fails' no-abort 'NO-CASES'

write_crate abort-defined bifrost-iroh 'impl Transport for E {}'
write_suite abort-defined 'use bifrost_iroh::Endpoint;
fn t() { identity_binding(a, b); wrong_key_rejected(a, b, c); }
fn an_aborted_writer_errors_the_peers_read(a: A, b: B) {}'
expect_fail 'defining the abort case is not calling it' abort-defined 'NO-CASES'

# The test-only rule: a test-only backend taken as a normal dependency fails, in either TOML form.
write_crate not-dev bifrost-mem 'impl Transport for M {}'
mkdir -p "$tmp/not-dev/app/src"
printf '[package]\nname = "app"\n\n[dependencies]\nbifrost-mem = { path = "../bifrost-mem" }\n' > "$tmp/not-dev/app/Cargo.toml"
expect_fail 'a test-only backend as a dependency fails' not-dev 'NOT-DEV'

write_crate not-dev-table bifrost-mem 'impl Transport for M {}'
mkdir -p "$tmp/not-dev-table/app/src"
printf '[package]\nname = "app"\n\n[dependencies.bifrost-mem]\npath = "../bifrost-mem"\n' > "$tmp/not-dev-table/app/Cargo.toml"
expect_fail 'a test-only backend as a dependency table fails' not-dev-table 'NOT-DEV'

# An empty tree (no manifests) passes.
mkdir -p "$tmp/empty"
expect_ok 'an empty tree passes' empty

printf '\nsealed-gate fixture: %s passed, %s failed.\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
