#!/bin/sh
# fork-watch.sh -- fail when an upstream advisory has not been checked against our fork of the crate.
#
# WHY. cargo-deny reads advisories filed against the crates in the lock, so it says nothing about a
# fork: an advisory against quinn-proto never names noq-proto, though noq-proto is quinn-proto's code
# under another name. RUSTSEC-2026-0185 went unseen in our lock that way. A watch by date (fail when
# upstream has an advisory newer than the fork's release) would not have caught it either: the
# advisory predates the noq-proto release that still lacked the fix. So the watch is keyed by
# advisory ID: every upstream advisory must have a row saying how our fork stands against it.
#
# THE LIST. scripts/fork-watch.txt, one row per (fork, upstream advisory), whitespace-separated:
#
#   <fork> <upstream> <advisory-id> ported
#   <fork> <upstream> <advisory-id> pinned <lock source>
#   <fork> <upstream> -
#
# `ported`: the fix is in the fork's locked code, checked by reading it. `pinned`: the fix is not in
# a release of the fork yet, and the lock takes it from <lock source> (the exact `source =` string in
# Cargo.lock). A `-` row names a fork whose upstream has no advisory today. A `#` that starts a line
# or follows a space starts a comment (a lock source carries one of its own).
#
# IT FAILS when:
#   (a) an advisory filed against an upstream in the list has no row for the fork,
#   (b) a `pinned` row's fork resolves from any source but the recorded one (the patch was dropped
#       or moved without a look at whether the release it moved to carries the fix),
#   (c) a fork in the list is not in Cargo.lock (a stale row), or
#   (d) a row is malformed.
#
# THE DATABASE. A shallow clone of https://github.com/rustsec/advisory-db, or the clone named by
# $ADVISORY_DB (the fixture uses that, so it runs offline). Withdrawn advisories still count: a row
# costs one line, and a missed one can cost a node.
#
# Dependency-free: POSIX sh + git + awk + grep + sed. Run from a repo root (or pass a root path):
#   sh scripts/fork-watch.sh [ROOT]

set -eu

ROOT="${1:-.}"
LIST="$ROOT/scripts/fork-watch.txt"
LOCK="$ROOT/Cargo.lock"

[ -f "$LIST" ] || { echo "fork-watch: no $LIST" >&2; exit 1; }
[ -f "$LOCK" ] || { echo "fork-watch: no $LOCK" >&2; exit 1; }

if [ -n "${ADVISORY_DB:-}" ]; then
  db="$ADVISORY_DB"
else
  tmp=$(mktemp -d)
  trap 'rm -rf "$tmp"' EXIT
  git clone --quiet --depth 1 https://github.com/rustsec/advisory-db "$tmp/advisory-db"
  db="$tmp/advisory-db"
fi
[ -d "$db/crates" ] || { echo "fork-watch: $db holds no crates/ directory" >&2; exit 1; }

# The rows, comments and blank lines dropped.
rows=$(sed -e 's/^#.*//' -e 's/[[:space:]]#.*//' -e '/^[[:space:]]*$/d' "$LIST")

# Every `source =` line of the lock's blocks for one package name, one per line ("none" for a block
# without one, which is a path or workspace crate).
lock_sources() {
  awk -v want="$1" '
    /^\[\[package\]\]/ { if (name == want) print (src == "" ? "none" : src); name = ""; src = ""; next }
    /^name = / { name = $3; gsub(/"/, "", name) }
    /^source = / { src = $3; gsub(/"/, "", src) }
    END { if (name == want) print (src == "" ? "none" : src) }
  ' "$LOCK"
}

fail=0
bad() { echo "fork-watch: $*" >&2; fail=1; }

# (d) the shape of each row.
printf '%s\n' "$rows" | while read -r fork upstream id status source extra; do
  case "$id:$status" in
    -:) ;;
    RUSTSEC-*:ported) [ -z "$source" ] || exit 1 ;;
    RUSTSEC-*:pinned) [ -n "$source" ] && [ -z "$extra" ] || exit 1 ;;
    *) exit 1 ;;
  esac
done || bad "a row of $LIST is malformed; see the header of scripts/fork-watch.sh for the shape"

forks=$(printf '%s\n' "$rows" | awk '{ print $1 " " $2 }' | sort -u)

# (c) and (a), per fork.
printf '%s\n' "$forks" | {
  fail=0
  while read -r fork upstream; do
    if [ -z "$(lock_sources "$fork")" ]; then
      echo "fork-watch: $fork is listed but not in Cargo.lock; drop its rows" >&2
      fail=1
    fi
    [ -d "$db/crates/$upstream" ] || continue
    for file in "$db/crates/$upstream"/RUSTSEC-*.md; do
      [ -f "$file" ] || continue
      id=$(basename "$file" .md)
      if ! printf '%s\n' "$rows" | awk -v f="$fork" -v u="$upstream" -v i="$id" \
        '$1 == f && $2 == u && $3 == i { found = 1 } END { exit !found }'; then
        echo "fork-watch: $id is filed against $upstream and $fork has no row for it; read the fix" \
          "against $fork's locked code and add a row (ported, or pinned to the source carrying it)" >&2
        fail=1
      fi
    done
  done
  exit "$fail"
} || fail=1

# (b) each pin still holds.
printf '%s\n' "$rows" | awk '$4 == "pinned" { print $1 " " $3 " " $5 }' | {
  fail=0
  while read -r fork id source; do
    for got in $(lock_sources "$fork"); do
      if [ "$got" != "$source" ]; then
        echo "fork-watch: $fork resolves from $got, but $id is pinned to $source; if a release" \
          "now carries the fix, mark the row ported, else restore the pin" >&2
        fail=1
      fi
    done
  done
  exit "$fail"
} || fail=1

if [ "$fail" -ne 0 ]; then
  exit 1
fi
echo "fork-watch: OK -- every upstream advisory has a row for its fork, and every pin holds."
