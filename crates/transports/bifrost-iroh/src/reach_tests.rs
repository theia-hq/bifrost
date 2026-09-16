//! What a relay origin and a resolver base accept, and every form they refuse.
//!
//! Each refusal here is a URL iroh's own parse accepts, so the case that matters is not a typo the
//! parse catches: it is a URL that would bind cleanly and then fail quietly, or carry the hop in
//! plaintext.

use crate::{ReachUrlError, RelayUrl, ResolverUrl};

#[test]
fn a_relay_origin_and_a_resolver_base_round_trip() {
    let relay: RelayUrl = "https://relay.example".parse().expect("a relay origin");
    assert_eq!(relay.to_string(), "https://relay.example/");

    let resolver: ResolverUrl = "https://dns.example/pkarr".parse().expect("a pkarr base");
    assert_eq!(resolver.to_string(), "https://dns.example/pkarr");
}

#[test]
fn a_scheme_other_than_https_is_refused() {
    for text in [
        "http://relay.example",
        "ws://relay.example",
        "wss://relay.example",
    ] {
        assert!(
            matches!(
                text.parse::<RelayUrl>(),
                Err(ReachUrlError::NotHttps { .. })
            ),
            "{text} must not pass as a relay origin"
        );
    }
    assert!(matches!(
        "http://dns.example/pkarr".parse::<ResolverUrl>(),
        Err(ReachUrlError::NotHttps { .. })
    ));
}

#[test]
fn credentials_in_the_url_are_refused() {
    assert!(matches!(
        "https://user@relay.example".parse::<RelayUrl>(),
        Err(ReachUrlError::Userinfo)
    ));
    assert!(matches!(
        "https://user:secret@dns.example/pkarr".parse::<ResolverUrl>(),
        Err(ReachUrlError::Userinfo)
    ));
}

#[test]
fn a_query_string_is_refused() {
    assert!(matches!(
        "https://relay.example?token=x".parse::<RelayUrl>(),
        Err(ReachUrlError::Query)
    ));
    assert!(matches!(
        "https://dns.example/pkarr?token=x".parse::<ResolverUrl>(),
        Err(ReachUrlError::Query)
    ));
}

#[test]
fn a_fragment_is_refused() {
    assert!(matches!(
        "https://relay.example#here".parse::<RelayUrl>(),
        Err(ReachUrlError::Fragment)
    ));
    assert!(matches!(
        "https://dns.example/pkarr#here".parse::<ResolverUrl>(),
        Err(ReachUrlError::Fragment)
    ));
}

/// A path on a relay origin is the mistake a pkarr base invites: the two URLs look alike and only
/// one of them takes a path.
#[test]
fn a_relay_origin_with_a_path_is_refused() {
    assert!(matches!(
        "https://relay.example/pkarr".parse::<RelayUrl>(),
        Err(ReachUrlError::RelayPath { .. })
    ));
    assert!(
        "https://relay.example/".parse::<RelayUrl>().is_ok(),
        "a bare origin renders with a root path, which is not a path"
    );
}

/// A URL parse refuses an empty host for `https` of its own accord, so there is no host check here to
/// carry the rule: this pins that the refusal arrives, and which one it is.
#[test]
fn a_url_with_no_host_is_refused() {
    for parsed in [
        "https://".parse::<RelayUrl>().err(),
        "https://".parse::<ResolverUrl>().err(),
    ] {
        assert!(matches!(
            parsed,
            Some(ReachUrlError::Malformed(url::ParseError::EmptyHost))
        ));
    }
}

/// A single-label host is the shape a typo lands on: `https:///pkarr` is not the empty host it looks
/// like, the url parse folds the extra slash away and reads `pkarr` as the host. Either form would
/// resolve through the machine's search domain, so it is a different server on every network.
#[test]
fn a_host_that_is_not_fully_qualified_is_refused() {
    for text in ["https:///pkarr", "https://pkarr"] {
        assert!(
            matches!(
                text.parse::<ResolverUrl>(),
                Err(ReachUrlError::UnqualifiedHost { .. })
            ),
            "{text} must not pass as a pkarr base"
        );
        assert!(
            matches!(
                text.parse::<RelayUrl>(),
                Err(ReachUrlError::UnqualifiedHost { .. })
            ),
            "{text} must not pass as a relay origin"
        );
    }
}

/// The relay client builds its TLS name from the host as written, brackets and all, and no
/// certificate name can match that, so the bind would come up and every relay connect would fail on
/// the name. The pkarr client reaches its base over a different stack and is unaffected.
#[test]
fn an_ipv6_literal_is_refused_as_a_relay_origin_only() {
    assert!(matches!(
        "https://[::1]".parse::<RelayUrl>(),
        Err(ReachUrlError::RelayIpv6)
    ));
    assert!(
        "https://[::1]/pkarr".parse::<ResolverUrl>().is_ok(),
        "a pkarr base may name an ipv6 literal"
    );
}

#[test]
fn port_zero_is_refused() {
    assert!(matches!(
        "https://relay.example:0".parse::<RelayUrl>(),
        Err(ReachUrlError::ZeroPort)
    ));
    assert!(matches!(
        "https://dns.example:0/pkarr".parse::<ResolverUrl>(),
        Err(ReachUrlError::ZeroPort)
    ));
}

/// A backslash is a path separator for `https`, so the host ends where the backslash begins: without
/// this refusal `https://evil.example\@relay.example` is a base on `evil.example` that reads to a
/// human like one on `relay.example`.
#[test]
fn a_backslash_in_the_text_is_refused() {
    assert!(matches!(
        r"https://evil.example\@relay.example".parse::<ResolverUrl>(),
        Err(ReachUrlError::Backslash)
    ));
    assert!(matches!(
        r"https://evil.example\@relay.example".parse::<RelayUrl>(),
        Err(ReachUrlError::Backslash)
    ));
}

#[test]
fn text_that_is_not_a_url_is_refused() {
    for text in ["", "relay.example", "https://:/"] {
        assert!(
            matches!(text.parse::<RelayUrl>(), Err(ReachUrlError::Malformed(_))),
            "{text} must not pass as a relay origin"
        );
    }
}

/// The pkarr client appends the peer's key as a path segment and keeps whatever slash is already
/// there, so a base is stored without its trailing one. Exactly one is dropped: a doubled slash was
/// typed on purpose or not at all, and either way it is not this parse's to guess at.
#[test]
fn a_resolver_base_drops_one_trailing_slash() {
    let dropped: ResolverUrl = "https://dns.example/pkarr/".parse().expect("a pkarr base");
    assert_eq!(dropped.to_string(), "https://dns.example/pkarr");

    let one_of_two: ResolverUrl = "https://dns.example/pkarr//".parse().expect("a pkarr base");
    assert_eq!(one_of_two.to_string(), "https://dns.example/pkarr/");

    // A base at the root has no segment to drop, and the root slash is not a trailing one: the key
    // is appended straight onto it.
    let root: ResolverUrl = "https://dns.example/".parse().expect("a pkarr base");
    assert_eq!(root.to_string(), "https://dns.example/");
}
