//! What each bind registers, how each bind reads a discovery feed, the two pins the type system
//! cannot make, the QUIC limits every bind applies, and a reach changed on a bound endpoint.
//!
//! iroh exposes the lookup services it was built with but no relay or certificate introspection, so
//! the lookup counts are asserted on a real bind and the rest is read off this crate's own source. A
//! removed pin fails here, not at the next upgrade. The feed read is [`Finding::seed`] driven with
//! fake feeds, since the choice between waiting and not never touches the network.
//!
//! A reach change is driven against relays and a pkarr server run on loopback. They speak plaintext,
//! which the public [`Reach`] refuses, so those tests hand the swap its relays and lookups directly
//! through [`Endpoint::swap`], the step [`Endpoint::set_reach`] takes after resolving a [`Reach`].

use core::future::Future as _;
use core::net::{IpAddr, Ipv4Addr, SocketAddr};
use core::pin::pin;
use core::task::{Context, Waker};
use core::time::Duration;
use std::path::{Path, PathBuf};
use std::{fs, io};

use bifrost_core::{
    Addr, AddrUpdate, ConnInfo, Discovery, Error, HintStream, KeyError, Layered, NodeId, Relay,
    StaticDiscovery,
};
use bifrost_transport::{Session as _, Transport as _};
use futures_util::{FutureExt as _, StreamExt as _, stream};
use iroh::test_utils::DnsPkarrServer;
use iroh::{EndpointAddr, RelayConfig, RelayMap, TransportAddr, Watcher as _};
use iroh_relay::server::{RelayConfig as RelayServerConfig, Server, ServerConfig};
use tokio::sync::oneshot;
use tokio::time;

use crate::reach::Role;
use crate::{
    ALPN, CONNECTION_WINDOW, Endpoint, Finding, IrohSession, OpenPath, Reach, RelayHome, Resolver,
    SetReachError, peer_of, reach,
};

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

/// F1 (0.9.1): the dialing bind registers the pkarr resolver and NO publisher. A second service would
/// be a publisher (or the DNS lookup) re-added to the dialing path, the exact regression.
#[tokio::test]
async fn the_dialing_bind_registers_no_publisher() {
    let lookups = lookups(
        Endpoint::bind_dialing_with_secret(&[7u8; 32])
            .await
            .expect("dialing bind"),
    )
    .await;
    assert_eq!(lookups.count, 1, "PkarrResolver only");
}

/// The n0 half is built from `presets::Minimal`, not delegated to `presets::N0`, so this counts what
/// the bind registers: the publisher and the pkarr resolver, and not the preset's DNS lookup.
#[tokio::test]
async fn the_serving_bind_registers_the_publisher_and_the_resolver() {
    let lookups = lookups(
        Endpoint::bind_reachable_with_secret(&[8u8; 32])
            .await
            .expect("serving bind"),
    )
    .await;
    assert_eq!(lookups.count, 2, "PkarrPublisher + PkarrResolver");
}

/// Discovery row D2: neither n0 bind asks the host's DNS resolver for a peer. That lookup queries
/// `_iroh.<key>` in plaintext on whatever network the host is on, naming whom this node dials, and a
/// count cannot tell which service came back, so this names the service. The positive half proves the
/// rendering names services at all, so an iroh rename cannot turn the absence into a vacuous pass.
#[tokio::test]
async fn no_n0_bind_registers_a_dns_lookup() {
    let binds = [
        (
            "dialing",
            Endpoint::bind_dialing_with_secret(&[11u8; 32])
                .await
                .expect("dialing bind"),
        ),
        (
            "serving",
            Endpoint::bind_reachable_with_secret(&[12u8; 32])
                .await
                .expect("serving bind"),
        ),
    ];
    for (role, endpoint) in binds {
        let lookups = lookups(endpoint).await;
        assert!(
            lookups.names("PkarrResolver"),
            "the {role} bind's lookups are not named: {}",
            lookups.rendered,
        );
        assert!(
            !lookups.names("DnsAddressLookup"),
            "the {role} bind asks the local DNS resolver: {}",
            lookups.rendered,
        );
    }
}

/// A named resolver is one pkarr server, so a dialing bind against it registers exactly one lookup:
/// no publisher (it serves nothing) and no DNS lookup (a pkarr base is not a delegated DNS origin).
#[tokio::test]
async fn a_named_resolver_registers_one_lookup_for_a_dialing_bind() {
    let lookups = lookups(
        Endpoint::bind_dialing_with_secret_via(&[9u8; 32], named_reach())
            .await
            .expect("dialing bind over a named reach"),
    )
    .await;
    assert_eq!(lookups.count, 1, "PkarrResolver only");
}

/// The serving bind adds the publisher against the same pkarr base, and nothing else.
#[tokio::test]
async fn a_named_resolver_registers_publisher_and_resolver_for_a_serving_bind() {
    let lookups = lookups(
        Endpoint::bind_reachable_with_secret_via(&[10u8; 32], named_reach())
            .await
            .expect("serving bind over a named reach"),
    )
    .await;
    assert_eq!(lookups.count, 2, "PkarrPublisher + PkarrResolver");
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

/// Every bind in this crate goes through `finish`, and `finish` hands iroh the limits right before it
/// binds: the one iroh `bind` call in the crate sits beside the transport config. A new bind path that
/// built its own endpoint and skipped `finish` would run on noq's defaults, and fails here.
#[test]
fn every_bind_applies_the_quic_limits() {
    // Assembled from halves: this file is under `src/` and the scan covers it too.
    let bind = [".bind", "()"].concat();
    let binds: usize = crate_sources()
        .iter()
        .map(|source| {
            fs::read_to_string(source)
                .expect("read a source file of this crate")
                .matches(&bind)
                .count()
        })
        .sum();
    assert_eq!(binds, 1, "one iroh bind in the crate, inside `finish`");

    let lib: String = include_str!("lib.rs").split_whitespace().collect();
    assert!(
        lib.contains(&[".transport_config(quic_limits())", &bind].concat()),
        "the bind in `finish` must apply `quic_limits()` as the last thing before it binds"
    );
}

/// A peer can send this node no datagram: neither side of a session advertises datagram support, so
/// each sees no room for one and a send fails at once rather than being buffered by the other side.
#[tokio::test]
async fn an_endpoint_refuses_application_datagrams() {
    let ((_dialer, dialed), (_host, accepted)) = local_session().await;
    for (side, session) in [("the dialer", &dialed), ("the host", &accepted)] {
        assert_eq!(
            session.conn.max_datagram_size(),
            None,
            "{side} sees a peer that takes datagrams"
        );
        assert!(
            session.conn.send_datagram(vec![1].into()).is_err(),
            "{side} could send a datagram"
        );
    }
}

/// A peer can open no unidirectional stream to this node: each side grants the other none, so an
/// open waits for credit that never comes.
#[tokio::test]
async fn an_endpoint_refuses_unidirectional_streams() {
    let ((_dialer, dialed), (_host, accepted)) = local_session().await;
    for (side, session) in [("the dialer", &dialed), ("the host", &accepted)] {
        assert!(
            time::timeout(STALL, session.conn.open_uni()).await.is_err(),
            "{side} opened a unidirectional stream"
        );
    }
}

/// A peer that opens streams the host never accepts can make it buffer the connection window and no
/// more: writes across twenty streams, each with room for a full stream window, stall once their sum
/// reaches it. Reading is what frees room, so once the host accepts and reads, a stalled stream moves.
#[tokio::test]
async fn a_peer_is_held_to_the_connection_budget() {
    const STREAMS: usize = 20;
    let window = usize::try_from(CONNECTION_WINDOW).expect("the window fits a usize");
    let ((_dialer, dialed), (_host, accepted)) = local_session().await;
    let chunk = vec![0u8; 64 * 1024];

    // `write` rather than `write_all`, so the bytes the host took are counted even when a write stalls
    // part way through a stream.
    let mut streams = Vec::with_capacity(STREAMS);
    let mut written = 0;
    for _ in 0..STREAMS {
        let (mut send, recv) = dialed.conn.open_bi().await.expect("open a stream");
        let mut sent = 0;
        while sent < STREAM_WINDOW {
            let room = (STREAM_WINDOW - sent).min(chunk.len());
            match time::timeout(STALL, send.write(&chunk[..room])).await {
                Ok(took) => sent += took.expect("write"),
                Err(_stalled) => break,
            }
        }
        written += sent;
        streams.push((send, recv));
    }
    assert!(
        written <= window,
        "the host buffered {written} bytes, past its {window}-byte window"
    );
    assert!(
        written > window - STREAM_WINDOW,
        "only {written} bytes went before every write stalled, short of the {window}-byte window"
    );

    // noq announces freed room once the reader has freed an eighth of the window (2 MiB), so the host
    // drains two whole streams rather than one.
    for _ in 0..2 {
        let (_back, mut heard) = time::timeout(BOUND, accepted.accept_bi())
            .await
            .expect("the host accepts in time")
            .expect("accept a stream");
        let mut body = vec![0u8; STREAM_WINDOW];
        time::timeout(BOUND, heard.read_exact(&mut body))
            .await
            .expect("the host reads in time")
            .expect("read a whole stream");
    }
    let (stalled, _) = streams.last_mut().expect("streams were opened");
    let took = time::timeout(BOUND, stalled.write(&chunk))
        .await
        .expect("a stalled stream moves once the host reads")
        .expect("write");
    assert!(took > 0, "the stalled stream took no bytes");
}

/// noq's per-stream receive window, which the QUIC limits leave as it is.
const STREAM_WINDOW: usize = 1_250_000;

/// How long a write or an open may wait before it counts as refused or stalled. Long enough that a
/// congestion pause on loopback is not mistaken for a flow-control stall.
const STALL: Duration = Duration::from_secs(1);

/// Two local endpoints with one session between them, the dialer's side first. Each endpoint is
/// returned beside its session so it outlives it.
async fn local_session() -> ((Endpoint, IrohSession), (Endpoint, IrohSession)) {
    let host = Endpoint::bind_local().await.expect("bind the host");
    let dialer = Endpoint::bind_local().await.expect("bind the dialer");
    let (dialed, accepted) = tokio::join!(
        time::timeout(BOUND, dialer.connect(host.local_addr())),
        time::timeout(BOUND, host.accept()),
    );
    let dialed = dialed
        .expect("the dial completes in time")
        .expect("the dial");
    let accepted = accepted
        .expect("the accept completes in time")
        .expect("the accept");
    ((dialer, dialed), (host, accepted))
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

/// `A + T`: the public key the seed `[7; 32]` binds plus the order-8 torsion point. iroh's key parse
/// only decompresses, so it takes these bytes as an endpoint id.
const TWIN_OF_SEVEN: [u8; NodeId::KEY_LEN] = [
    0x1f, 0x4f, 0x58, 0x0e, 0x73, 0xac, 0x20, 0x8f, 0x06, 0x76, 0x01, 0x90, 0xe9, 0xed, 0xc6, 0xf5,
    0x91, 0x67, 0x75, 0xda, 0xbd, 0x9c, 0x1c, 0xdc, 0xa3, 0x93, 0x17, 0x5c, 0x2d, 0x6d, 0x10, 0x83,
];

/// iroh accepts the twin as an endpoint id and its TLS check is `verify_strict`, which the twin's holder
/// can pass; the peer parse is what refuses it, while the untwisted id parses to the same `NodeId` the
/// secret derives.
#[test]
fn a_twin_endpoint_id_is_refused_by_peer_of() {
    let twin = iroh::EndpointId::from_bytes(&TWIN_OF_SEVEN).expect("iroh decompresses the twin");
    assert_eq!(peer_of(twin), Err(KeyError::HasTorsion));

    let untwisted = iroh::SecretKey::from_bytes(&[7; 32]).public();
    assert_eq!(
        peer_of(untwisted),
        Ok(NodeId::from_ed25519_secret(&[7; NodeId::KEY_LEN]))
    );
}

/// A hole-punched session keeps its relay path open as a standby beside the direct one. The bytes
/// take the direct path iroh selected, so the session is direct, with that path's rtt and address.
#[test]
fn a_direct_path_with_a_standby_relay_is_direct() {
    let paths = [
        Open::standby(relay_addr(), RELAY_RTT),
        Open::carrying(TransportAddr::Ip(hint()), DIRECT_RTT),
    ];
    assert_eq!(
        crate::conn_info(&paths),
        ConnInfo {
            path: bifrost_core::Path::Direct,
            rtt: Some(DIRECT_RTT),
            remote: Some(hint()),
        }
    );
}

/// The inversion: the same two paths with the relay selected is relayed, naming that relay, with no
/// direct address, since none carries the bytes.
#[test]
fn a_relayed_path_with_a_standby_direct_is_relayed() {
    let paths = [
        Open::carrying(relay_addr(), RELAY_RTT),
        Open::standby(TransportAddr::Ip(hint()), DIRECT_RTT),
    ];
    let relay = Relay::from(url::Url::from(relay_url()));
    assert_eq!(
        crate::conn_info(&paths),
        ConnInfo {
            path: bifrost_core::Path::Relayed(relay),
            rtt: Some(RELAY_RTT),
            remote: None,
        }
    );
}

/// Open paths with none selected (before the first selection, or just after the selected one closed)
/// carry no bytes, so the path is unknown rather than read off whichever happens to be open.
#[test]
fn open_paths_with_none_selected_are_unknown() {
    let paths = [
        Open::standby(relay_addr(), RELAY_RTT),
        Open::standby(TransportAddr::Ip(hint()), DIRECT_RTT),
    ];
    assert_eq!(crate::conn_info(&paths), ConnInfo::default());
}

/// A session set up through a relay opens its path stream naming that relay, then says when iroh
/// moves its bytes to the direct path it punched, at the moment of the selection. The relay path
/// stays open as a standby and the session reads direct: the live form of the selection tests above.
/// Once the session is closed and dropped, the stream ends.
#[tokio::test]
async fn a_relayed_session_says_when_its_bytes_move_direct() {
    let (_relay, relay) = local_relay().await;
    let served = serving(31).await;
    swap(&served, &relay, None).await;
    home_is(&served, &relay).await;
    let dialer = serving(32).await;
    swap(&dialer, &relay, None).await;
    home_is(&dialer, &relay).await;

    // The handshake itself crosses the relay, and punching needs a round trip after it, so the
    // session is still relayed when it is handed over.
    let (dialed, accepted) = dial(&dialer, &served, &relay).await;
    let mut changes = accepted.path_changes();
    let through = bifrost_core::Path::Relayed(Relay::from(url::Url::from(relay)));
    assert_eq!(changes.next().await, Some(through));

    let moved = time::timeout(BOUND, changes.next())
        .await
        .expect("the path changes in time");
    assert_eq!(moved, Some(bifrost_core::Path::Direct));
    assert!(
        accepted.conn.paths().iter().any(|path| path.is_relay()),
        "the relay path stays open as a standby"
    );
    assert_eq!(accepted.conn_info().path, bifrost_core::Path::Direct);

    accepted.close();
    drop((accepted, dialed));
    let ended = time::timeout(BOUND, async { while changes.next().await.is_some() {} }).await;
    assert!(ended.is_ok(), "the stream ends after the session closes");
    served.close().await;
    dialer.close().await;
}

/// A swap moves the home relay of an endpoint that is already serving: the connection opened over
/// the old relay stays open, and once the old relay is gone a peer still reaches the endpoint, and is
/// answered, through the new one.
#[tokio::test]
async fn a_reach_change_moves_the_home_relay_on_a_bound_endpoint() {
    let (old_relay, old) = local_relay().await;
    let (_new_relay, new) = local_relay().await;
    let moved = serving(21).await;
    swap(&moved, &old, None).await;
    home_is(&moved, &old).await;
    let peer = serving(22).await;
    swap(&peer, &new, None).await;
    home_is(&peer, &new).await;
    let before = dial(&peer, &moved, &old).await;

    swap(&moved, &new, None).await;
    home_is(&moved, &new).await;
    echo(before).await;

    // With the old relay gone, a dialer that has never met this endpoint, and so knows no direct
    // path to it, can only make first contact through the new relay.
    old_relay.shutdown().await.expect("stop the old relay");
    let stranger = serving(27).await;
    swap(&stranger, &new, None).await;
    home_is(&stranger, &new).await;
    echo(dial(&stranger, &moved, &new).await).await;
    moved.close().await;
    peer.close().await;
    stranger.close().await;
}

/// A swap of resolver publishes this endpoint's record through the new one at once, and resolves
/// through the new one only.
#[tokio::test]
async fn a_resolver_change_publishes_through_the_new_resolver() {
    let (_relay, relay) = local_relay().await;
    let first = DnsPkarrServer::run().await.expect("run the first resolver");
    let second = DnsPkarrServer::run()
        .await
        .expect("run the second resolver");
    let moved = serving(23).await;
    swap(&moved, &relay, Some(lookups_at(&first))).await;
    first
        .on_endpoint(&moved.inner.id(), BOUND)
        .await
        .expect("the record goes to the first resolver");

    swap(&moved, &relay, Some(lookups_at(&second))).await;
    second
        .on_endpoint(&moved.inner.id(), BOUND)
        .await
        .expect("the record goes to the new resolver");

    // The test resolver takes records and serves none back, so the resolving half is read off the
    // running services: the new resolver's, and nothing left of the old one's.
    let services = moved
        .inner
        .address_lookup()
        .expect("a live endpoint reports its lookups");
    let rendered = format!("{services:?}");
    assert_eq!(services.len(), 2, "PkarrPublisher + PkarrResolver");
    assert!(
        rendered.contains(&format!("{:?}", second.pkarr_url())),
        "the new resolver is in use: {rendered}"
    );
    assert!(
        !rendered.contains(&format!("{:?}", first.pkarr_url())),
        "the old resolver is gone: {rendered}"
    );
    moved.close().await;
}

/// A relay the endpoint cannot reach is applied, and the old home stays in use: iroh keeps its home
/// relay when no relay in the new map answers. The swap is real (the old relay leaves the map, so
/// the next network report no longer measures it); the home is what does not move.
#[tokio::test]
async fn an_unreachable_relay_keeps_the_old_home() {
    let (_relay, old) = local_relay().await;
    let moved = serving(25).await;
    swap(&moved, &old, None).await;
    home_is(&moved, &old).await;

    let unreachable = Reach {
        relay: RelayHome::Custom("https://elsewhere.invalid".parse().expect("a relay origin")),
        ..named_reach()
    };
    moved
        .set_reach(unreachable.clone())
        .await
        .expect("a bound endpoint takes a reach");
    assert_eq!(moved.reach().await, Some(unreachable));
    let live = live_relays(&moved).await;
    assert!(
        !live.contains(&old) && live.len() == 1,
        "the old relay left iroh's map for the new one: {live:?}"
    );

    let mut reports = moved.inner.net_report();
    time::timeout(BOUND, async {
        loop {
            let measured_old = reports.get().is_some_and(|report| {
                report
                    .relay_latency
                    .iter()
                    .any(|(_probe, url, _latency)| *url == old)
            });
            if !measured_old {
                return;
            }
            reports.updated().await.expect("the endpoint is alive");
        }
    })
    .await
    .expect("a network report without the old relay, which left the map");

    // The home moves after the report is published, so a read right after it could still see the old
    // home on an iroh that clears it. Hold the claim over a window long enough for that to land.
    let mut home = moved.inner.home_relay_status();
    let moved_off = time::timeout(SETTLE, async {
        loop {
            if !home
                .get()
                .iter()
                .any(|status| *status.url() == old && status.is_connected())
            {
                return;
            }
            home.updated().await.expect("the endpoint is alive");
        }
    })
    .await;
    assert!(
        moved_off.is_err(),
        "the home left the old relay: {:?}",
        home.get()
    );
    let home = home.get();
    assert!(
        home.iter()
            .any(|status| *status.url() == old && status.is_connected()),
        "the old home stays in use: {home:?}"
    );
    moved.close().await;
}

/// A dialing endpoint resolves through the new resolver after a swap and still publishes nothing:
/// a swap keeps the role it was bound with. The hosts are `.invalid`, so this touches no network.
#[tokio::test]
async fn a_dialing_endpoint_stays_resolver_only_after_a_reach_change() {
    let dialing = Endpoint::bind_dialing_with_secret_via(&[26u8; 32], named_reach())
        .await
        .expect("dialing bind over a named reach");
    let base = "https://other.invalid/pkarr";
    dialing
        .set_reach(Reach {
            resolver: Resolver::Custom(base.parse().expect("a pkarr base")),
            ..named_reach()
        })
        .await
        .expect("a bound endpoint takes a reach");

    let lookups = lookups(dialing).await;
    assert_eq!(lookups.count, 1, "PkarrResolver only: {}", lookups.rendered);
    assert!(lookups.names("PkarrResolver"), "{}", lookups.rendered);
    assert!(!lookups.names("PkarrPublisher"), "{}", lookups.rendered);
    let new_base = format!("{:?}", url::Url::parse(base).expect("a url"));
    assert!(
        lookups.rendered.contains(&new_base),
        "the new resolver is in use: {}",
        lookups.rendered
    );
}

/// A local or offline bind has no relay or resolver, so it refuses a reach and reports none.
#[tokio::test]
async fn a_local_bind_refuses_a_reach_change() {
    let local = Endpoint::bind_local().await.expect("local bind");
    assert!(matches!(
        local.set_reach(Reach::default()).await,
        Err(SetReachError::Local)
    ));
    assert_eq!(local.reach().await, None);
    local.close().await;
}

/// How long a test waits on a relay, a resolver or a network report before calling it a failure.
const BOUND: Duration = Duration::from_secs(20);

/// How long a claim that something does NOT change is held before it is believed.
const SETTLE: Duration = Duration::from_secs(2);

/// The URLs in iroh's live relay map, read through the map the bind handed it.
async fn live_relays(endpoint: &Endpoint) -> Vec<iroh::RelayUrl> {
    let applied = endpoint.reach.as_ref().expect("a reachable bind");
    applied.lock().await.live.urls()
}

/// A relay on loopback, in plaintext, with no QUIC address discovery: the network report measures it
/// over HTTP alone, which is enough for it to become a home.
async fn local_relay() -> (Server, iroh::RelayUrl) {
    let mut config = ServerConfig::default();
    config.relay = Some(RelayServerConfig::new((Ipv4Addr::LOCALHOST, 0)));
    let server = Server::spawn(config).await.expect("run a relay");
    let addr = server.http_addr().expect("the relay serves http");
    let url = format!("http://{addr}").parse().expect("a relay url");
    (server, url)
}

/// A serving bind over the named reach, whose hosts resolve nowhere, so it reaches no network until
/// a test swaps a loopback relay or resolver onto it.
async fn serving(seed: u8) -> Endpoint {
    Endpoint::bind_reachable_with_secret_via(&[seed; 32], named_reach())
        .await
        .expect("serving bind")
}

/// The lookups a serving endpoint registers against a loopback pkarr server.
fn lookups_at(resolver: &DnsPkarrServer) -> reach::Lookups {
    reach::Lookups::at(resolver.pkarr_url().clone(), Role::Serving)
}

/// Swap `relay` and, when given, `lookups` onto a bound endpoint, through the same step
/// [`Endpoint::set_reach`] takes.
async fn swap(endpoint: &Endpoint, relay: &iroh::RelayUrl, lookups: Option<reach::Lookups>) {
    let applied = endpoint.reach.as_ref().expect("a reachable bind");
    let mut applied = applied.lock().await;
    let relays = RelayMap::from(RelayConfig::new(relay.clone(), None));
    endpoint
        .swap(&mut applied.relays, &relays, lookups)
        .await
        .expect("a live endpoint takes a swap");
}

/// Wait until `relay` is the endpoint's connected home.
async fn home_is(endpoint: &Endpoint, relay: &iroh::RelayUrl) {
    let mut home = endpoint.inner.home_relay_status();
    time::timeout(BOUND, async {
        loop {
            if home
                .get()
                .iter()
                .any(|status| status.url() == relay && status.is_connected())
            {
                return;
            }
            home.updated().await.expect("the endpoint is alive");
        }
    })
    .await
    .unwrap_or_else(|_| panic!("{relay} becomes the home: {:?}", home.get()));
}

/// `from` dials `to` naming only `relay`, and `to` accepts. The address carries no socket, so the
/// session is set up through the relay or not at all.
async fn dial(
    from: &Endpoint,
    to: &Endpoint,
    relay: &iroh::RelayUrl,
) -> (iroh::endpoint::Connection, crate::IrohSession) {
    let addr = EndpointAddr::new(to.inner.id()).with_relay_url(relay.clone());
    let (dialed, accepted) = tokio::join!(
        time::timeout(BOUND, from.inner.connect(addr, ALPN)),
        time::timeout(BOUND, to.accept()),
    );
    let dialed = dialed
        .expect("the dial completes in time")
        .expect("the dial through the relay");
    let accepted = accepted
        .expect("the accept completes in time")
        .expect("the accept");
    (dialed, accepted)
}

/// One byte each way over a fresh stream of a session `dial` opened.
async fn echo((dialed, accepted): (iroh::endpoint::Connection, crate::IrohSession)) {
    let (mut send, mut recv) = dialed.open_bi().await.expect("open a stream");
    send.write_all(&[1]).await.expect("send");
    let (mut back, mut heard) = accepted.accept_bi().await.expect("accept the stream");
    let mut byte = [0u8; 1];
    heard.read_exact(&mut byte).await.expect("hear the byte");
    back.write_all(&byte).await.expect("answer");
    recv.read_exact(&mut byte).await.expect("hear the answer");
    assert_eq!(byte, [1]);
}

/// A reach whose halves are both the caller's own. The hosts are `.invalid`, which resolves nowhere
/// by definition, so a bind over this one registers its services and reaches no network.
/// The peer every feed test dials.
fn peer() -> NodeId {
    NodeId::from_ed25519_secret(&[0x51; NodeId::KEY_LEN])
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

/// The lookup services a bind registered. iroh keeps the services private and exposes only their
/// count and a `Debug` rendering, which names each service by its type, so both are kept.
struct Lookups {
    count: usize,
    rendered: String,
}

impl Lookups {
    /// Whether a service of this type name was registered.
    fn names(&self, service: &str) -> bool {
        self.rendered.contains(service)
    }
}

/// Reads what a bind registered. Consumes the endpoint: the services are read before the close so the
/// answer is about a live endpoint, and every bind here is closed rather than dropped.
async fn lookups(endpoint: Endpoint) -> Lookups {
    let services = endpoint
        .inner
        .address_lookup()
        .expect("a live endpoint reports its lookups");
    let lookups = Lookups {
        count: services.len(),
        rendered: format!("{services:?}"),
    };
    endpoint.close().await;
    lookups
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

/// Every persisted-identity bind borrows the secret and returns a future that no longer does, so a
/// caller can bind through `secret.with_bytes(..)` and the seed never has to be copied out. The seed
/// is dropped before each future is used: a future that still borrowed it would not compile here.
#[test]
fn a_bind_future_holds_no_borrow_of_the_secret() {
    fn owns_everything<F: Future + Send + 'static>(bind: F) -> F {
        bind
    }
    let seed = Box::new([7u8; 32]);
    let binds = (
        owns_everything(Endpoint::bind_reachable_with_secret(&seed)),
        owns_everything(Endpoint::bind_dialing_with_secret(&seed)),
        owns_everything(Endpoint::bind_reachable_with_secret_via(
            &seed,
            Reach::default(),
        )),
        owns_everything(Endpoint::bind_dialing_with_secret_via(
            &seed,
            Reach::default(),
        )),
        owns_everything(Endpoint::bind_local_with_secret(&seed)),
        owns_everything(Endpoint::bind_offline(
            &seed,
            SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
        )),
    );
    drop(seed);
    drop(binds);
}

/// One open path as [`crate::conn_info`] reads it, standing in for the path iroh builds only on a live
/// connection.
struct Open {
    selected: bool,
    remote: TransportAddr,
    rtt: Duration,
}

impl Open {
    /// The path iroh selected to carry bytes.
    fn carrying(remote: TransportAddr, rtt: Duration) -> Self {
        Self {
            selected: true,
            remote,
            rtt,
        }
    }

    /// A path held open but not selected.
    fn standby(remote: TransportAddr, rtt: Duration) -> Self {
        Self {
            selected: false,
            remote,
            rtt,
        }
    }
}

impl OpenPath for &Open {
    fn is_selected(&self) -> bool {
        self.selected
    }

    fn remote_addr(&self) -> &TransportAddr {
        &self.remote
    }

    fn rtt(&self) -> Duration {
        self.rtt
    }
}

/// The relay a relayed path in the selection tests goes through.
fn relay_url() -> iroh::RelayUrl {
    "https://relay.example".parse().expect("a relay url")
}

/// [`relay_url`] as a path's remote address.
fn relay_addr() -> TransportAddr {
    TransportAddr::Relay(relay_url())
}

/// A direct path's rtt in the selection tests, far below [`RELAY_RTT`] so a swap of the two shows.
const DIRECT_RTT: Duration = Duration::from_micros(400);

/// A relayed path's rtt in the selection tests.
const RELAY_RTT: Duration = Duration::from_millis(38);
