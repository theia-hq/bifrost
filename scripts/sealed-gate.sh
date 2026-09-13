#!/bin/sh
# sealed-gate.sh -- only an audited transport crate may declare `type Security = Sealed`.
#
# THE RULE (delib-61; notes/reviews/2026-09-13-adversary-transport-profile.md, MAJOR-1). `Sealed` is
# a claim the compiler cannot verify: any crate can write the declaration and satisfy the
# `PeerProven`/`Secure` bounds. This gate makes the claim visible: the crates allowed to make it are
# listed here, each with the audit backing it, and a declaration anywhere else fails CI.
#
# WHAT IT CHECKS. Every `type Security = Sealed` in a crate's `src/` tree, across the manifests found
# under ROOT. The trait impl is the shipped declaration; a `tests/` or `examples/` double is not a
# transport and is out of scope. The marker definition and the generated `impl SecurityProfile for
# Sealed` in bifrost-transport never spell `type Security = Sealed`, so they do not match.
#
# ESCAPE HATCH. A declaration may carry `sealed-gate:allow` in a comment on the same line. That is a
# deliberate, reviewed exception whose reason must ride in the diff (the same shape as the layering
# gate's marker). Prefer adding the crate to REVIEWED_SEALED once its handshake and channel have an
# Adversary review.
#
# TO ADD A CRATE. Append its package name to REVIEWED_SEALED with a one-line citation of the review
# that audited it. This list IS the reviewed allowlist; adding an entry is the explicit reviewed act.
#
# Dependency-free: POSIX sh + find + grep + sed. Run from a repo root (or pass a root path):
#   sh scripts/sealed-gate.sh [ROOT]

set -eu

ROOT="${1:-.}"
ALLOW_MARK="sealed-gate:allow"

# The audited transports, each with the review that backed it:
#   bifrost-iroh  -- QUIC + TLS 1.3 raw public keys; 2026-09-13-adversary-transport-profile.md
#   bifrost-noise -- Noise_XX_25519_ChaChaPoly_SHA256 + signed fresh statics;
#                    2026-09-13-adversary-bifrost-noise.md
REVIEWED_SEALED="bifrost-iroh bifrost-noise"

# The declaration as rustc reads it. Comment lines are skipped below: a doc may spell the shape of
# the declaration without shipping one (the admission checklist in bifrost-transport does).
PATTERN='type[[:space:]]+Security[[:space:]]*=[[:space:]]*Sealed'

manifests=$(find "$ROOT" -name Cargo.toml -not -path '*/target/*' -not -path '*/_archived/*' | sort)

fail=0
declarations=0
audited_crates=0

for manifest in $manifests; do
  [ -n "$manifest" ] || continue
  grep -q '^\[package\]' "$manifest" || continue
  dir=$(dirname "$manifest")
  [ -d "$dir/src" ] || continue
  own=$(sed -n 's/^name[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' "$manifest" | head -n1)
  [ -n "$own" ] || continue

  srcs=$(find "$dir/src" -name '*.rs' 2>/dev/null)
  [ -n "$srcs" ] || continue
  hits=$(grep -En "$PATTERN" $srcs 2>/dev/null | grep -Ev ':[[:space:]]*//' | grep -v "$ALLOW_MARK" || true)
  [ -n "$hits" ] || continue

  declarations=$((declarations + $(printf '%s\n' "$hits" | grep -c .)))

  case " $REVIEWED_SEALED " in
    *" $own "*)
      audited_crates=$((audited_crates + 1))
      ;;
    *)
      printf 'UNREVIEWED  crate %s declares Sealed without an audit:\n' "$own"
      printf '%s\n' "$hits" | sed 's/^/        /'
      printf '        add %s to REVIEWED_SEALED in scripts/sealed-gate.sh once its handshake\n' "$own"
      printf '        and channel have an Adversary review, or mark a deliberate exception\n'
      printf '        with "%s" on the declaration line.\n' "$ALLOW_MARK"
      fail=1
      ;;
  esac
done

if [ "$fail" -ne 0 ]; then
  printf '\nsealed-gate: FAIL -- a transport declared the strongest profile outside the reviewed set.\n' >&2
  exit 1
fi
printf 'sealed-gate: OK -- %s Sealed declaration(s) in %s audited crate(s).\n' \
  "$declarations" "$audited_crates"
