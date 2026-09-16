#!/bin/sh
# sealed-gate.sh -- a crate may declare only the security profile its review authorized.
#
# THE RULE (delib-61; delib-72; notes/reviews/2026-09-13-adversary-transport-profile.md, MAJOR-1). A
# proof-bearing profile (`Sealed`, `InProcess`) is a claim the compiler cannot verify: any crate can
# write the declaration and satisfy the `PeerProven`/`Secure` bounds, and `InProcess` implements both
# capabilities (`bifrost-transport/src/security.rs`), so on a wire transport it is a second free
# spelling of the strongest effective claim. This gate makes the claim visible: the crates allowed to
# make it are listed here as a per-crate profile table, each with the review backing it, and a
# declaration outside the table fails CI. A literal `Announced` declaration is free: it claims neither
# capability, so a bounded consumer refuses it at compile time and an engine serves it open-only; the
# gate watches only the proof-bearing pair.
# The admission checklist a review runs lives in `bifrost-transport/src/lib.rs` (28-52); it is cited,
# never copied here.
#
# WHAT IT CHECKS. Every `type Security = Sealed|InProcess` in a crate's `src/` tree, across the
# manifests found under ROOT: a hit must name exactly the profile the crate's table entry authorizes
# (no entry = no proof-bearing profile), and the comparison is per hit on the declaration token, so
# trailing text cannot mask the declaration. A `[package]` whose name line the gate cannot read
# fails loud rather than being skipped. The trait impl is the shipped declaration; a `tests/` or
# `examples/` double is not a transport and is out of scope, though an in-`src` test module IS scanned
# and must obey the same rule. The marker definitions and the generated `impl SecurityProfile` in
# bifrost-transport never spell either declaration, so they do not match.
#
# THE ENTRY CONTRACT. A `crate=profile` pair asserts: this crate's claim to `profile` is reviewed; the
# citation comment beside the pair names the review that ran the admission checklist and records the
# evidence state (battery report, capture substitute, or owed). The machine checks membership and the
# profile match, NOT the citation: the citations are not machine-checked. An entry with no matching
# declaration is not reported; the failure direction is benign (a renamed crate fails CI at its next
# declaration, and the diff review prompts the table update).
#
# ESCAPE HATCH. A declaration may carry `sealed-gate:allow <review-ref>` in a comment on the same line,
# where `<review-ref>` is a non-empty citation of the review that authorized the exception. The ref is
# required (a bare marker is NOT an escape and fails as a declaration), and the OK line counts the
# exceptions so each one is visible in the CI log, not only in the diff. Prefer adding the crate to
# REVIEWED_PROFILES once its handshake and channel have an Adversary review.
#
# OUT OF REACH (stated, not implied): an aliased or path-qualified right-hand side
# (`type Security = crate::Sealed;`), a declaration split across lines, an unknown profile token
# (`SealedExt`), macro emission, an `include!` from outside `src/`, a `[lib] path` outside `src/`, a
# non-`.rs` template, a crate in another repo (this gate scans ROOT only), a comment between `Security`
# and `=` (`type Security /* x */ = Sealed` is not matched), a `#[path = "..."] mod` that pulls a source
# from outside `src/`, a `[package]` name the parse cannot read (it fails loud, see below, rather than
# being scanned), a second declaration inside a listed crate (the entry is per crate, so every hit in a
# listed crate rides its one profile; the hits are printed so the set is visible), and a PR that edits
# this gate or the table in the same diff (review is the control there).
#
# Dependency-free: POSIX sh + find + grep + sed. Run from a repo root (or pass a root path):
#   sh scripts/sealed-gate.sh [ROOT]

set -eu

ROOT="${1:-.}"
ALLOW_MARK="sealed-gate:allow"

# The reviewed profile table: one `crate=profile` pair per reviewed crate, with the citation and
# evidence state the entry asserts (see THE ENTRY CONTRACT above):
#   bifrost-iroh  = Sealed     -- 2026-09-13-adversary-transport-profile.md; per-backend Sealed
#                                 evidence OWED: iroh is untappable, so the substitute is one OS
#                                 capture at a named rev plus the named protocol review (post-0.9)
#   bifrost-noise = Sealed     -- 2026-09-13-adversary-bifrost-noise.md; the FIX-FIRST fixes landed
#                                 (06127fe); battery evidence OWED (the wrapper leg over `Tap` is the
#                                 first post-0.9 battery addition)
#   bifrost-mem   = InProcess  -- test-only backend (no wire); not a `Sealed` claim, so no battery
#                                 evidence is owed
REVIEWED_PROFILES="bifrost-iroh=Sealed bifrost-noise=Sealed bifrost-mem=InProcess"

# The declaration as rustc reads it, with the profile token delimited so `SealedExt` is not a match.
# Comment-leading lines are skipped below: a doc may spell the shape of the declaration without
# shipping one (the admission checklist in bifrost-transport does).
PATTERN='type[[:space:]]+Security[[:space:]]*=[[:space:]]*(Sealed|InProcess)([^A-Za-z0-9_]|$)'
# The RHS token of a `type Security =` spelling, for the per-hit comparison below: the FIRST match on
# a hit decides, so text later on the line cannot mask the declaration.
DECL='type[[:space:]]+Security[[:space:]]*=[[:space:]]*[A-Za-z0-9_]+'
# A cited exception: the marker followed by a non-empty review ref.
ALLOW_RE='sealed-gate:allow[[:space:]]+[^[:space:]]'

manifests=$(find "$ROOT" -name Cargo.toml -not -path '*/target/*' -not -path '*/_archived/*' | sort)

fail=0
reviewed_decls=0
reviewed_crates=0
exceptions=0

for manifest in $manifests; do
  [ -n "$manifest" ] || continue
  grep -q '^\[package\]' "$manifest" || continue
  dir=$(dirname "$manifest")
  [ -d "$dir/src" ] || continue
  # Read the name from the `[package]` section ONLY: an earlier `name =` line (a `[lib] name`, a
  # `[workspace.package]` field, a dependency rename) must not spoof the crate's identity. The gate
  # parses a double-quoted TOML string only; a `[package]` name it cannot read (`name = 'liar'`)
  # fails loud, because skipping the crate would make its declarations invisible (Adversary P-1,
  # notes/reviews/2026-09-16-adversary-sealed-hatch-signoff.md).
  own=$(sed -n '/^\[package\]/,/^\[/s/^name[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' "$manifest" | head -n1)
  if [ -z "$own" ]; then
    printf 'UNPARSED    %s has a [package] section with no name line the gate can read.\n' "$manifest"
    printf '        The gate parses a flush-left, double-quoted `name = "..."` only; a single-quoted,\n'
    printf '        quoted-key, or indented spelling leaves the crate unidentified, so write the name\n'
    printf '        that way as the first line after `[package]`.\n'
    fail=1
    continue
  fi

  srcs=$(find "$dir/src" -name '*.rs' 2>/dev/null)
  [ -n "$srcs" ] || continue
  # `-H` keeps the filename on every hit, even for a single source file; the comment filter is anchored
  # to the start of the SOURCE line, so a trailing comment (an audit citation, a URL) cannot suppress a
  # declaration, and a source file that cannot be read is loud rather than silent.
  found=$(grep -HEn "$PATTERN" $srcs | grep -Ev '^[^:]*:[[:digit:]]+:[[:space:]]*//' || true)
  [ -n "$found" ] || continue

  # Cited exceptions are dropped from enforcement but counted in the OK line.
  cited=$(printf '%s\n' "$found" | grep -E "$ALLOW_RE" || true)
  hits=$(printf '%s\n' "$found" | grep -Ev "$ALLOW_RE" || true)
  if [ -n "$cited" ]; then
    exceptions=$((exceptions + $(printf '%s\n' "$cited" | grep -c . || true)))
  fi
  [ -n "$hits" ] || continue

  n_hits=$(printf '%s\n' "$hits" | grep -c . || true)

  # The crate's allowed profile, from the table.
  allowed=""
  for pair in $REVIEWED_PROFILES; do
    case $pair in
      "$own"=*) allowed=${pair#*=} ;;
    esac
  done

  if [ -n "$allowed" ]; then
    # Per hit, the RHS token of the FIRST `type Security =` match decides (MAJOR-1): a whole-line
    # match lets trailing text that spells the allowed profile mask a disallowed declaration, e.g.
    # `type Security = Sealed;` with a trailing `type Security = InProcess` mention in a crate
    # reviewed for InProcess, reproduced both directions in
    # notes/reviews/2026-09-16-rust-reviewer-inc1.md.
    bad=$(printf '%s\n' "$hits" | while IFS= read -r hit; do
      [ -n "$hit" ] || continue
      token=$(printf '%s\n' "$hit" | grep -oE "$DECL" | head -n1 | sed 's/^[^=]*=[[:space:]]*//')
      [ "$token" = "$allowed" ] || printf '%s\n' "$hit"
    done)
  else
    bad=$hits
  fi

  if [ -n "$bad" ]; then
    printf 'UNREVIEWED  crate %s declares a profile it is not reviewed for:\n' "$own"
    printf '%s\n' "$bad" | sed 's/^/        /'
    printf '        add or update this crate in REVIEWED_PROFILES in scripts/sealed-gate.sh once\n'
    printf '        its handshake and channel have an Adversary review, or mark a deliberate\n'
    printf '        exception with "%s <review-ref>" on the declaration line.\n' "$ALLOW_MARK"
    fail=1
  else
    reviewed_decls=$((reviewed_decls + n_hits))
    reviewed_crates=$((reviewed_crates + 1))
    printf 'REVIEWED    %s\n' "$own"
    printf '%s\n' "$hits" | sed 's/^/        /'
  fi
done

if [ "$fail" -ne 0 ]; then
  printf '\nsealed-gate: FAIL -- a crate profile cannot be matched to the reviewed table.\n' >&2
  exit 1
fi
printf 'sealed-gate: OK -- %s reviewed profile declaration(s) in %s crate(s), %s cited exception(s).\n' \
  "$reviewed_decls" "$reviewed_crates" "$exceptions"
