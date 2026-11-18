#!/bin/sh
# sealed-gate.sh -- only the listed crates may implement `Transport` or `Session`.
#
# THE RULE. A shipping transport's `Session::peer` promises that its handshake proved the peer holds the
# key, and no type checks that promise: any crate that writes `impl Transport for` or `impl Session for`
# makes it. This gate keeps the list of crates allowed to, and such an impl in the `src/` tree of any
# other crate under ROOT fails CI. The list holds two kinds of crate:
#   - a backend that cleared the admission checklist in `bifrost-transport/src/lib.rs` ("Admitting a
#     new transport"; cited, never copied here). Today that is iroh.
#   - a test-only backend, marked `:test`. Today that is mem: it has no handshake and proves nothing
#     about a peer (every identity's secret is computable). The gate fails any manifest under ROOT
#     that takes a test-only backend as anything but a dev-dependency.
#
# THE REQUIRED CASES. Each listed backend that is not test-only and has its manifest under ROOT
# must have a file under some `tests/` directory in ROOT that names its library (`bifrost_iroh`) and
# calls every case in REQUIRED_CASES, or the gate fails. Two are the identity cases,
# `identity_binding(` and `wrong_key_rejected(`. The limit: both pass for a transport that echoes the
# dialed key with no handshake (`bifrost-conformance/src/lib.rs`, on
# `claimed_identity_not_attributed`), so they falsify a fabricator and never prove a handshake. The
# third is the abort case, `an_aborted_writer_errors_the_peers_read(`: the trait bound makes every
# backend implement an abort, and only this case shows the abort reaches the peer as an error rather
# than as a clean end. The fourth is the delivery case, `a_delivered_stream_survives_a_close(`: a
# close after `delivered` is safe only if the backend keeps the bytes its peer acknowledged readable
# past the close, which no type shows and only this case checks. The file must also name
# `Delivery::Acknowledged`, the form in which the peer reads only after the close; the read-as-it-goes
# form would let a backend pass without that check. And the gate checks that the calls and the name share a file, not that the
# calls run that transport.
#
# WHAT IT CHECKS. Every line in a crate's `src/` tree that starts an impl of either trait, named bare,
# raw (`r#Transport`), or by path (`::bifrost_transport::Transport`, `$crate::Session`), with `for`
# on the same line or, as rustfmt splits a long header, on the next. A comment-leading line is
# skipped, so a doc may spell the shape; a trailing comment does not hide an impl. An in-`src` test
# module IS scanned. A `[package]` whose name line the gate cannot read fails loud rather than being
# skipped, since skipping it would hide its impls.
#
# OUT OF REACH (stated, not implied): an impl header split anywhere but before `for`, a trait alias
# or a `use ... as` rename, macro emission other than `$crate::`, an `include!` or `#[path]` source
# from outside `src/`, a `[lib] path` outside `src/`, test doubles under `tests/` or `examples/`, a
# dependency renamed with `package = "..."`, and every crate in another repo (this gate scans ROOT
# only).
#
# Dependency-free: POSIX sh + find + grep + sed + awk. Run from a repo root (or pass a root path):
#   sh scripts/sealed-gate.sh [ROOT]

set -eu

ROOT="${1:-.}"

# The transport crates. A `:test` suffix marks a test-only backend.
#   bifrost-iroh      -- cleared the checklist; runs the required cases in
#                        bifrost-conformance/tests/roundtrip.rs
#   bifrost-mem:test  -- no handshake, proves nothing; a dev-dependency only
TRANSPORT_CRATES="bifrost-iroh bifrost-mem:test"

# The conformance cases every listed backend that is not test-only must call from one `tests/` file.
REQUIRED_CASES="identity_binding wrong_key_rejected an_aborted_writer_errors_the_peers_read a_delivered_stream_survives_a_close"
# The tokens the same file must name, matched as fixed strings: which form a case runs in.
REQUIRED_TOKENS="Delivery::Acknowledged"
# The same names as one alternation, to drop the lines that define a case rather than call it.
defined=$(printf '%s' "$REQUIRED_CASES" | tr ' ' '|')

# The impl header: `impl`, optional generics, an optional path (`::`, `$crate::`, raw segments), then
# the trait token, raw or not, delimited on both sides so `SubTransport` and `TransportExt` are not a
# match, then `for` or the end of the line.
PATTERN='(^|[^A-Za-z0-9_])impl([[:space:]]*<.*>)?[[:space:]]+(::)?(\$?(r#)?[A-Za-z0-9_]+::)*(r#)?(Transport|Session)([[:space:]]+for([^A-Za-z0-9_]|$)|[[:space:]]*$)'
# A source line that is a comment from its start.
COMMENT='^[^:]*:[[:digit:]]+:[[:space:]]*//'

manifests=$(find "$ROOT" -name Cargo.toml -not -path '*/target/*' -not -path '*/_archived/*' | sort)
tests=$(find "$ROOT" -path '*/tests/*' -name '*.rs' -not -path '*/target/*' -not -path '*/_archived/*' | sort)

fail=0
impls=0
# The listed crates whose manifest is under ROOT: only those owe the required cases here.
present=""

for manifest in $manifests; do
  [ -n "$manifest" ] || continue
  grep -q '^\[package\]' "$manifest" || continue
  dir=$(dirname "$manifest")
  [ -d "$dir/src" ] || continue
  # Read the name from the `[package]` section ONLY: an earlier `name =` line (a `[lib] name`, a
  # `[workspace.package]` field, a dependency rename) must not let a crate pass as a listed one.
  own=$(sed -n '/^\[package\]/,/^\[/s/^name[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' "$manifest" | head -n1)
  if [ -z "$own" ]; then
    printf 'UNPARSED    %s has a [package] section with no name line the gate can read.\n' "$manifest"
    printf '        The gate parses a flush-left, double-quoted `name = "..."` only; write the name\n'
    printf '        that way as the first line after `[package]`.\n'
    fail=1
    continue
  fi
  for entry in $TRANSPORT_CRATES; do
    [ "$entry" = "$own" ] && present="$present $own"
  done

  srcs=$(find "$dir/src" -name '*.rs' 2>/dev/null)
  [ -n "$srcs" ] || continue
  # `-H` keeps the filename on every hit, even for a single source file; the comment filter is anchored
  # to the start of the SOURCE line, so a trailing comment cannot hide an impl.
  found=$(grep -HEn "$PATTERN" $srcs | grep -Ev "$COMMENT" || true)
  [ -n "$found" ] || continue

  listed=0
  for entry in $TRANSPORT_CRATES; do
    [ "${entry%:test}" = "$own" ] && listed=1
  done

  if [ "$listed" -eq 1 ]; then
    impls=$((impls + $(printf '%s\n' "$found" | grep -c . || true)))
    printf 'LISTED      %s\n' "$own"
    printf '%s\n' "$found" | sed 's/^/        /'
  else
    printf 'UNLISTED    crate %s implements Transport or Session but is not a listed transport crate:\n' "$own"
    printf '%s\n' "$found" | sed 's/^/        /'
    printf '        a new backend clears the admission checklist in bifrost-transport, runs the\n'
    printf '        required cases, and is then added to TRANSPORT_CRATES in scripts/sealed-gate.sh.\n'
    fail=1
  fi
done

for entry in $TRANSPORT_CRATES; do
  crate=${entry%:test}
  if [ "$entry" != "$crate" ]; then
    # A test-only backend: every manifest line that takes it must sit in a dev-dependency table (or
    # the workspace table that only declares it). A `[...dependencies.<crate>]` header counts too.
    bad=$(for manifest in $manifests; do
      awk -v t="$crate" '
        /^[[:space:]]*\[/ {
          sec = $0; gsub(/[[:space:]]/, "", sec)
          if (index(sec, "." t "]") && sec !~ /dev-dependencies\./ && sec !~ /^\[workspace\.dependencies\./)
            print FILENAME ":" NR ": " $0
          next
        }
        $0 ~ ("^[[:space:]]*\"?" t "\"?[[:space:]]*[=.]") {
          if (sec !~ /dev-dependencies\]$/ && sec != "[workspace.dependencies]")
            print FILENAME ":" NR ": " $0
        }' "$manifest"
    done)
    if [ -n "$bad" ]; then
      printf 'NOT-DEV     test-only backend %s is taken as more than a dev-dependency:\n' "$crate"
      printf '%s\n' "$bad" | sed 's/^/        /'
      fail=1
    fi
    continue
  fi

  # A backend that is not test-only and is in this tree: some `tests/` file names its library and
  # calls every required case.
  case " $present " in
    *" $crate "*) ;;
    *) continue ;;
  esac
  lib=$(printf '%s' "$crate" | tr '-' '_')
  runs=0
  for t in $tests; do
    code=$(grep -Ev '^[[:space:]]*//' "$t" || true)
    printf '%s\n' "$code" | grep -Eq "(^|[^A-Za-z0-9_])$lib([^A-Za-z0-9_]|$)" || continue
    # A definition is not a call: a line declaring one of the cases is dropped before the search.
    calls=$(printf '%s\n' "$code" | grep -Ev "fn[[:space:]]+($defined)" || true)
    every=1
    for case_name in $REQUIRED_CASES; do
      printf '%s\n' "$calls" | grep -Eq "(^|[^A-Za-z0-9_])$case_name[[:space:]]*\\(" || every=0
    done
    for token in $REQUIRED_TOKENS; do
      printf '%s\n' "$code" | grep -Fq "$token" || every=0
    done
    [ "$every" -eq 1 ] || continue
    runs=1
    printf 'CASES       %s runs the required cases in %s\n' "$crate" "$t"
    break
  done
  if [ "$runs" -eq 0 ]; then
    printf 'NO-CASES    listed backend %s has no tests/ file that names %s and calls every one of\n' "$crate" "$lib"
    printf '        %s, naming %s.\n' "$REQUIRED_CASES" "$REQUIRED_TOKENS"
    fail=1
  fi
done

if [ "$fail" -ne 0 ]; then
  printf '\nsealed-gate: FAIL -- the transport list does not hold.\n' >&2
  exit 1
fi
printf 'sealed-gate: OK -- %s Transport/Session impl(s), all in listed crates (%s).\n' "$impls" "$TRANSPORT_CRATES"
