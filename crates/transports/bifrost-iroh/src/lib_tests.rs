//! What each bind registers, how each bind reads a discovery feed, and the two pins the type
//! system cannot make.
//!
//! iroh exposes the lookup services it was built with but no relay or certificate introspection, so
//! the lookup counts are asserted on a real bind and the rest is read off this crate's own source. A
//! removed pin fails here, not at the next upgrade. The feed read is [`Finding::seed`] driven with
//! fake feeds, since the choice between waiting and not never touches the network.

use core::future::Future as _;
use core::net::{IpAddr, Ipv4Addr, SocketAddr};
use core::pin::pin;
use core::task::{Context, Waker};
use std::path::{Path, PathBuf};
use std::{fs, io};

use bifrost_core::{
    Addr, AddrUpdate, CryptoKind, Discovery, Error, HintStream, Layered, NodeId, StaticDiscovery,
};
use bifrost_transport::Transport as _;
use futures_util::{FutureExt as _, stream};
use tokio::sync::oneshot;

use crate::{Endpoint, Finding, Reach, RelayHome, Resolver};

/// A bind that finds peers by key dials at once over a feed that never answers; a hints-only bind
/// has nothing to dial yet, so it is still waiting.
#[test]
fn by_key_does_not_wait_on_a_silent_feed() {
    let seeded = Finding::ByKey
        .seed(bare(), silent())
        .now_or_never()
        .expect("a by-key bind must not wait on the feed");
    assert_eq!(
        seeded.expect("a silent feed is no failure").hints,
        Vec::new()
    );

    assert!(
        Finding::ByHints
            .seed(bare(), silent())
            .now_or_never()
            .is_none(),
        "a hints-only bind waits for the feed's first answer"
    );
}

/// Not waiting is not ignoring: a hint the feed already holds (a caller's hint in the fixed table
/// beside a learned source still looking) rides the by-key dial, through the real union.
#[test]
fn by_key_carries_a_hint_the_feed_already_holds() {
    let mut table = StaticDiscovery::new();
    table.insert(peer(), vec![hint()]);
    let feed = Layered::new(table, Silent).subscribe(peer());

    let seeded = Finding::ByKey
        .seed(bare(), feed)
        .now_or_never()
        .expect("a by-key bind must not wait on the feed");

    assert_eq!(seeded.expect("the feed holds a hint").hints, vec![hint()]);
}

/// A hints-only bind dials with the answer that arrives after the dial began; a by-key bind given
/// the same late feed has already gone with what it held.
#[tokio::test]
async fn by_hints_waits_for_the_first_answer() {
    let (feed, answer) = late();
    let mut seeding = pin!(Finding::ByHints.seed(bare(), feed));
    assert!(
        seeding
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending(),
        "nothing is dialed before the feed answers"
    );
    answer.send(()).expect("the seeding is still listening");
    let seeded = seeding.await.expect("the late answer is no failure");
    assert_eq!(seeded.hints, vec![hint()]);

    let (feed, _answer) = late();
    let seeded = Finding::ByKey
        .seed(bare(), feed)
        .now_or_never()
        .expect("a by-key bind must not wait for a late answer");
    assert_eq!(seeded.expect("no answer is no failure").hints, Vec::new());
}

/// A feed whose first word is a failure fails the dial under either bind: not waiting is no
/// licence to swallow an error the feed has already given.
#[test]
fn a_ready_error_fails_either_bind() {
    for finding in [Finding::ByKey, Finding::ByHints] {
        let seeded = finding
            .seed(bare(), failing())
            .now_or_never()
            .expect("a ready failure is read at once");
        assert!(
            matches!(seeded, Err(Error::Connect(_))),
            "{finding:?} must fail on a failed feed"
        );
    }
}

/// F1 (0.9.1): the dialing bind registers the two resolvers and NO publisher. A third service would
/// be a publisher re-added to the dialing path, the exact regression.
#[tokio::test]
async fn the_dialing_bind_registers_no_publisher() {
    let services = lookup_services(
        Endpoint::bind_dialing_with_secret([7u8; 32])
            .await
            .expect("dialing bind"),
    )
    .await;
    assert_eq!(services, 2, "PkarrResolver + DnsAddressLookup only");
}

/// The n0 half is reproduced from `presets::Minimal`, not delegated to `presets::N0`, so this counts
/// what the preset registers today: the publisher, the pkarr resolver, and the DNS lookup.
#[tokio::test]
async fn the_serving_bind_registers_the_publisher_and_both_resolvers() {
    let services = lookup_services(
        Endpoint::bind_reachable_with_secret([8u8; 32])
            .await
            .expect("serving bind"),
    )
    .await;
    assert_eq!(
        services, 3,
        "PkarrPublisher + PkarrResolver + DnsAddressLookup"
    );
}

/// A named resolver is one pkarr server, so a dialing bind against it registers exactly one lookup:
/// no publisher (it serves nothing) and no DNS lookup (a pkarr base is not a delegated DNS origin).
#[tokio::test]
async fn a_named_resolver_registers_one_lookup_for_a_dialing_bind() {
    let services = lookup_services(
        Endpoint::bind_dialing_with_secret_via([9u8; 32], named_reach())
            .await
            .expect("dialing bind over a named reach"),
    )
    .await;
    assert_eq!(services, 1, "PkarrResolver only");
}

/// The serving bind adds the publisher against the same pkarr base, and nothing else.
#[tokio::test]
async fn a_named_resolver_registers_publisher_and_resolver_for_a_serving_bind() {
    let services = lookup_services(
        Endpoint::bind_reachable_with_secret_via([10u8; 32], named_reach())
            .await
            .expect("serving bind over a named reach"),
    )
    .await;
    assert_eq!(services, 2, "PkarrPublisher + PkarrResolver");
}

/// The "no NAT traversal" claim is a mechanism, not an absence: iroh exposes no public relay or
/// portmapper introspection, so the pin is the constructor's two explicit disable calls and this
/// test reads them off the source. Removing a pin fails here, not at the next iroh upgrade.
#[test]
fn the_local_constructor_pins_relay_and_portmapper_off() {
    let source = include_str!("lib.rs");
    assert!(
        source.contains(".relay_mode(RelayMode::Disabled)"),
        "bind_local_with_secret must pin RelayMode::Disabled (no relay fallback)"
    );
    assert!(
        source.contains(".portmapper_config(PortmapperConfig::Disabled)"),
        "bind_local_with_secret must pin PortmapperConfig::Disabled (no gateway probing)"
    );
}

/// The `https` pin is only worth what certificate verification is worth: a relay or a resolver a
/// caller runs must present a certificate a public root signed, or it is not a host this crate will
/// talk to. iroh offers a public hatch that skips that check, and reaching for it to make a
/// self-signed host work would hollow out every refusal the reach module makes, so neither the
/// builder call that installs a certificate policy nor the skip-verification constructor may appear
/// anywhere in this crate.
#[test]
fn no_source_here_reaches_for_the_certificate_hatch() {
    // The needles are assembled from halves because this file is under `src/` and the scan covers it
    // too: spelled whole, each one would be its own hit.
    let hatches = [
        ["ca_tls", "_config"].concat(),
        ["ca_roots", "_config"].concat(),
        ["insecure_skip", "_verify"].concat(),
        ["make_dangerous", "_client_config"].concat(),
    ];
    for source in crate_sources() {
        let text = fs::read_to_string(&source).expect("read a source file of this crate");
        for hatch in &hatches {
            assert!(
                !text.contains(hatch),
                "{}: a caller-run relay or resolver needs a publicly-signed certificate, so `{hatch}` \
                 must not appear in this crate",
                source.display()
            );
        }
    }
}

/// The declared profile is PINNED per backend: every consumer's trust decision rests on it, so an
/// accidental flip fails HERE, in the crate that declares it, rather than downstream in code that went on
/// believing the old promise. `Sealed` is the profile the `bifrost-iroh` entry in
/// `scripts/sealed-gate.sh` authorizes.
#[test]
fn the_declared_profile_is_pinned_to_sealed() {
    use bifrost_transport::SecurityProfile as _;

    assert_eq!(
        <Endpoint as bifrost_transport::Transport>::Security::SECURITY,
        bifrost_transport::Sealed::SECURITY
    );
}

/// A reach whose halves are both the caller's own. The hosts are `.invalid`, which resolves nowhere
/// by definition, so a bind over this one registers its services and reaches no network.
/// The peer every feed test dials.
fn peer() -> NodeId {
    NodeId::new(CryptoKind::Ed25519, [0x51; NodeId::KEY_LEN])
}

/// The dial address a caller holds before discovery: the key and no hints.
fn bare() -> Addr {
    Addr::from_node(peer())
}

/// The one hint a feed here answers with.
fn hint() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 7101)
}

/// A feed that never answers and never ends.
fn silent() -> HintStream {
    HintStream::new(stream::pending())
}

/// A feed that answers with [`hint`] once the returned sender fires, and not before.
fn late() -> (HintStream, oneshot::Sender<()>) {
    let (answer, heard) = oneshot::channel();
    let feed = stream::unfold(Some(heard), |heard| async move {
        heard?.await.ok()?;
        Some((Ok(AddrUpdate::Hints(vec![hint()])), None))
    });
    (HintStream::new(feed), answer)
}

/// A feed whose first word is a failure.
fn failing() -> HintStream {
    HintStream::new(stream::iter([Err(Error::Connect(Box::new(
        io::Error::other("source down"),
    )))]))
}

/// A source that never answers, to sit beside the fixed table as a learned source still looking.
struct Silent;

impl Discovery for Silent {
    fn subscribe(&self, _node: NodeId) -> HintStream {
        silent()
    }
}

fn named_reach() -> Reach {
    Reach {
        relay: RelayHome::Custom("https://relay.invalid".parse().expect("a relay origin")),
        resolver: Resolver::Custom("https://dns.invalid/pkarr".parse().expect("a pkarr base")),
    }
}

/// How many lookup services a bind registered. Consumes the endpoint: the count is read before the
/// close so the answer is about a live endpoint, and every bind here is closed rather than dropped.
async fn lookup_services(endpoint: Endpoint) -> usize {
    let services = endpoint
        .inner
        .address_lookup()
        .expect("a live endpoint reports its lookups")
        .len();
    endpoint.close().await;
    services
}

/// Every `.rs` file under this crate's `src/`, so a pin that scans the source covers a module added
/// later instead of only the files it was written against.
fn crate_sources() -> Vec<PathBuf> {
    let mut found = Vec::new();
    collect(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("src"),
        &mut found,
    );
    assert!(!found.is_empty(), "this crate has source files");
    found
}

fn collect(dir: PathBuf, found: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).expect("read a source directory of this crate") {
        let path = entry.expect("read a source directory entry").path();
        if path.is_dir() {
            collect(path, found);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            found.push(path);
        }
    }
}

