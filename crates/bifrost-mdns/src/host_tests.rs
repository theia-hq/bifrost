//! The expansion itself: which sockets a bind answers on, how far each of them reaches, and what
//! survives an interface list the host will not hand over.
//!
//! Enumeration runs against a handed [`HostAddrs`] rather than the machine's real interfaces, so
//! these assert the policy itself and hold on any host, CI included.

use core::net::{IpAddr, SocketAddr};
use std::io;

use if_addrs::{IfAddr, IfOperStatus, Ifv4Addr, Interface};

use crate::MdnsError;
use crate::host::{At, Dialable, Expiring, Gaps, HostAddr, HostAddrs, Missing, Scope, ScopeClass};
use crate::publish::Advertising;

/// A wildcard bind means "every interface", so it answers at this host's concrete addresses on the
/// bound port, and at loopback, which the same socket also answers on.
#[test]
fn a_wildcard_answers_at_the_hosts_addresses_and_at_loopback() {
    let host = host_addrs();

    let dialable = host.expand(vec![socket("0.0.0.0", 51979)]);

    assert_eq!(
        dialable,
        vec![
            at("192.168.1.5", 51979, Scope::Network),
            at("10.0.0.7", 51979, Scope::Network),
            at("127.0.0.1", 51979, Scope::ThisMachine),
        ],
        "the wildcard stands for the host's v4 addresses on the bound port, loopback included"
    );
}

/// A concrete bind answers at exactly itself and is never expanded: a caller that bound `127.0.0.1`
/// asked for a host-local service, and expanding it into this host's other addresses would claim a
/// reach it deliberately did not bind.
#[test]
fn a_concrete_bind_answers_at_exactly_itself() {
    let host = host_addrs();

    assert_eq!(
        host.expand(vec![socket("127.0.0.1", 9000)]),
        vec![at("127.0.0.1", 9000, Scope::ThisMachine)]
    );
    assert_eq!(
        host.expand(vec![socket("192.168.1.5", 9000)]),
        vec![at("192.168.1.5", 9000, Scope::Network)]
    );
}

/// A v4 wildcard takes the host's v4 addresses and a v6 wildcard its v6 ones, loopback included in
/// its own family. Crossing families would name an address on a socket that never bound it.
#[test]
fn a_wildcard_expands_within_its_own_family() {
    let host = host_addrs();

    assert_eq!(
        host.expand(vec![socket("[::]", 51987)]),
        vec![
            at("[2001:db8::5]", 51987, Scope::Network),
            at("[::1]", 51987, Scope::ThisMachine),
        ]
    );
}

/// Two wildcards on one port describe the same interfaces, and the same socket derived twice would
/// be published and pinned twice, and handed over twice, for no gain.
#[test]
fn an_expansion_yields_each_socket_once() {
    let host = host_addrs();

    assert_eq!(
        host.expand(vec![socket("0.0.0.0", 4000), socket("0.0.0.0", 4000)]),
        vec![
            at("192.168.1.5", 4000, Scope::Network),
            at("10.0.0.7", 4000, Scope::Network),
            at("127.0.0.1", 4000, Scope::ThisMachine),
        ]
    );
}

/// A point-to-point link (utun, tun, wg, a tailnet) is kept and MARKED, not dropped: the socket
/// observably answers there, so it is an address a person can hand to a peer on that same overlay.
/// The mark names the link, which is what says who can route to it, and the order puts it below
/// every address with a whole network behind it and above the one that never leaves this machine.
#[test]
fn a_point_to_point_link_is_a_marked_tunnel_entry_below_the_network_ones() {
    let host = HostAddrs::of_interfaces(vec![
        interface("utun4", "100.100.201.59", Running::Yes, PointToPoint::Yes),
        interface("en0", "192.168.1.5", Running::Yes, PointToPoint::No),
        interface("lo0", "127.0.0.1", Running::Yes, PointToPoint::No),
    ]);

    assert_eq!(
        host.expand(vec![socket("0.0.0.0", 50663)]),
        vec![
            at("192.168.1.5", 50663, Scope::Network),
            at(
                "100.100.201.59",
                50663,
                Scope::Tunnel {
                    link: "utun4".to_owned()
                }
            ),
            at("127.0.0.1", 50663, Scope::ThisMachine),
        ],
        "the tunnel address carries the link it rides, and sorts between network and loopback"
    );
}

/// A tunnel address is handable and stays unpublishable: nothing that hears this node's multicast
/// query arrives over a point-to-point link, so the record carries the network address alone.
#[test]
fn a_tunnel_address_is_handable_and_never_published() {
    let bound = vec![socket("0.0.0.0", 50663)];
    let host = HostAddrs::of_interfaces(vec![
        interface("en0", "192.168.1.5", Running::Yes, PointToPoint::No),
        interface("utun4", "100.100.201.59", Running::Yes, PointToPoint::Yes),
    ]);

    let advertising = Advertising::of_dialable(
        Dialable::of_host(Ok((host, Gaps::Nothing)), bound.clone()),
        &bound,
    );

    let Advertising::OnLan(advertised) = advertising else {
        panic!("the network address reaches the LAN, got {advertising:?}");
    };
    assert_eq!(
        advertised.addrs(),
        [socket("192.168.1.5", 50663)],
        "the tunnel address and the wildcard's loopback are both left off the wire"
    );
}

/// An interface the OS does not report running is not one this node answers on, and a link-local
/// address is unusable to either consumer: no record and no pasted address carries the scope it
/// needs to mean anything.
#[test]
fn a_down_link_and_a_link_local_address_are_left_out() {
    let host = HostAddrs::of_interfaces(vec![
        interface("en0", "192.168.1.5", Running::Yes, PointToPoint::No),
        interface("en1", "192.168.2.5", Running::No, PointToPoint::No),
        interface("en2", "169.254.11.4", Running::Yes, PointToPoint::No),
    ]);

    assert_eq!(
        host.expand(vec![socket("0.0.0.0", 51979)]),
        vec![
            at("192.168.1.5", 51979, Scope::Network),
            at("127.0.0.1", 51979, Scope::ThisMachine),
        ]
    );
}

/// The link-local guard holds on the address list too, so a `fe80::` cannot reach a consumer even if
/// the interface list it came from was assembled some other way.
#[test]
fn a_link_local_address_is_never_yielded() {
    let host = HostAddrs(vec![
        host_addr("fe80::1", Scope::Network),
        host_addr("2001:db8::5", Scope::Network),
    ]);

    assert_eq!(
        host.expand(vec![socket("[::]", 51987)]),
        vec![
            at("[2001:db8::5]", 51987, Scope::Network),
            at("[::1]", 51987, Scope::ThisMachine),
        ]
    );
}

/// A wildcard on a host with no address of its own still answers somewhere: loopback, which is what
/// a second process on this machine dials, so a surface always has an address to hand over. It
/// publishes nothing all the same, because nothing in that set is an address another host could
/// dial.
#[test]
fn a_wildcard_on_an_isolated_host_is_handable_at_loopback_and_publishes_nothing() {
    let bound = vec![socket("0.0.0.0", 51979)];
    let dialable = Dialable::of_host(Ok((HostAddrs(Vec::new()), Gaps::Nothing)), bound.clone());

    assert_eq!(
        dialable.all(),
        [at("127.0.0.1", 51979, Scope::ThisMachine)],
        "the wildcard answers on loopback whatever the host reports"
    );
    assert!(matches!(
        Advertising::of_dialable(dialable, &bound),
        Advertising::BrowseOnly(MdnsError::NoAddrs)
    ));
}

/// An interface list the host will not hand over is not an error either consumer has to branch on:
/// the expansion stays TOTAL, yielding what is derivable without it, and carries the cause so the
/// consumer whose own outcome depends on the read (the publisher) can report it.
#[test]
fn a_failed_interface_read_carries_its_cause_and_still_answers_at_loopback() {
    let bound = vec![socket("0.0.0.0", 51979), socket("127.0.0.1", 9000)];
    let failed = Err(io::Error::other("no interfaces here"));

    let dialable = Dialable::of_host(failed, bound.clone());

    assert_eq!(
        dialable.all(),
        [
            at("127.0.0.1", 51979, Scope::ThisMachine),
            at("127.0.0.1", 9000, Scope::ThisMachine),
        ],
        "the wildcard's loopback and the concrete bind survive a read that failed"
    );
    assert!(
        matches!(dialable.missing(), Missing::Interfaces(_)),
        "the cause rides along rather than being swallowed"
    );
    assert!(
        matches!(
            Advertising::of_dialable(dialable, &bound),
            Advertising::BrowseOnly(MdnsError::Interfaces(_))
        ),
        "the publisher reports the same cause as its own outcome"
    );
}

/// A consumer renders the short list off what is missing, so it has to be able to BUILD one: a
/// branch over [`Dialable::missing`] that no test of its own can reach is the branch that came
/// back missing. Assembled with a cause, the value is an expanded one in every other respect.
#[test]
fn an_assembled_set_can_carry_what_made_it_short() {
    let dialable = Dialable::short(
        [
            at("127.0.0.1", 51979, Scope::ThisMachine),
            at("192.168.1.5", 51979, Scope::Network),
        ],
        Missing::Interfaces(io::Error::other("no interfaces here")),
    );

    assert_eq!(
        dialable.all(),
        [
            at("192.168.1.5", 51979, Scope::Network),
            at("127.0.0.1", 51979, Scope::ThisMachine),
        ],
        "an assembled set is ordered exactly as an expansion would order it"
    );
    assert!(
        matches!(dialable.missing(), Missing::Interfaces(_)),
        "the cause is what the whole constructor is for"
    );
}

/// What the report is per CLASS for: a drop that EMPTIES a class is the thing an operator can act
/// on, and a tally cannot say whether one happened. A deprecated unique-local address says nothing
/// about whether this host still has an internet address; two counted drops say nothing at all.
#[test]
fn what_was_dropped_as_expiring_says_which_class_lost_an_address() {
    let dialable = bind_over_drops(
        vec![socket("[::]", 51987)],
        vec![
            v6("en0", "2605:59c1:18c2:df08:7c65:e101:392a:62b1"),
            v6("en0", "fde2:7482:8f60:8:1cd3:29d9:f098:aa4b"),
        ],
    );

    let dropped = report(&dialable);
    assert_eq!(dropped.count(), 2, "one entry per dropped address");
    assert!(
        dropped.reached(ScopeClass::Internet),
        "the global address that went is what makes the internet class worth a word"
    );
    assert!(
        dropped.reached(ScopeClass::Network),
        "the unique-local one is a separate loss, not the same one counted twice"
    );
    assert!(
        !dropped.reached(ScopeClass::ThisMachine),
        "a class nothing was dropped from lost nothing"
    );
}

/// A drop counts only where it would have become an entry. An address on a link this host does not
/// report as running was never going to be handed to anyone, so calling it lost sends a consumer
/// looking for a row that was never coming; and nothing dropped is no gap at all, never an empty
/// one.
#[test]
fn a_drop_this_host_would_never_have_handed_over_is_not_reported() {
    let down = Interface {
        oper_status: IfOperStatus::Down,
        ..v6("en1", "2605:59c1:18c2:df08:7c65:e101:392a:62b1")
    };

    assert!(
        matches!(Gaps::expiring(vec![down]), Gaps::Nothing),
        "the link is down, so the address it carried was never an entry to lose"
    );
    assert!(
        matches!(Gaps::expiring(Vec::new()), Gaps::Nothing),
        "nothing dropped is nothing to report"
    );
}

/// THE case the narrowing exists for. A bind that expands one family alone, which is every
/// transport that binds `0.0.0.0` and nothing else, never had a row in the other family, so an
/// address dropped there leaves a gap the BIND already explains. Reported, it would have a
/// consumer tell its operator to wait out an expiry for a row that was never coming.
#[test]
fn a_drop_in_a_family_this_bind_never_expands_is_not_this_binds_drop() {
    let dialable = bind_over_drops(vec![socket("0.0.0.0", 51979)], both_families_dropped());

    let dropped = report(&dialable);
    assert_eq!(
        dropped.count(),
        1,
        "only the v4 drop is one this bind could have been short of"
    );
    assert!(
        !dropped.reached(ScopeClass::Internet),
        "the global v6 address went, and this bind never had an internet row to lose"
    );
    assert!(
        dropped.reached(ScopeClass::Network),
        "the v4 drop is this bind's own, and stands whatever happened in the other family"
    );
}

/// The other half of the same fact: the SAME drop against a bind that does expand v6 is reported,
/// so the narrowing is about which families this bind answers on and never about the v6 family
/// being worth less.
#[test]
fn a_dual_stack_bind_reports_the_drop_a_v4_only_bind_could_not() {
    let dialable = bind_over_drops(
        vec![socket("0.0.0.0", 51979), socket("[::]", 51979)],
        both_families_dropped(),
    );

    let dropped = report(&dialable);
    assert_eq!(dropped.count(), 2, "both drops are this bind's own");
    assert!(
        dropped.reached(ScopeClass::Internet),
        "the bind expands v6, so the global v6 address it lost is a class that went short"
    );
}

/// Narrowing can take everything, and a report of nothing is not a report: the consumer branches on
/// the variant, so an empty one would render an expiry clause over a set that lost nothing.
#[test]
fn a_drop_narrowed_down_to_nothing_leaves_nothing_missing() {
    let dialable = bind_over_drops(
        vec![socket("0.0.0.0", 51979)],
        vec![v6("en0", "2605:59c1:18c2:df08:7c65:e101:392a:62b1")],
    );

    assert!(
        matches!(dialable.missing(), Missing::Nothing),
        "the one drop was in a family this bind never expands, so the set is missing nothing"
    );
}

/// A concrete bind expands to nothing but itself, so no address this host is about to stop
/// answering on was ever a row it could lose. [`Dialable::of`] never even reads the interfaces for
/// such a bind; this pins that the seam underneath agrees, rather than leaving the two paths to
/// disagree the day something else reads the host first.
#[test]
fn a_concrete_bind_expands_nothing_so_no_drop_is_its_own() {
    let dialable = bind_over_drops(vec![socket("192.168.1.5", 9000)], both_families_dropped());

    assert!(
        matches!(dialable.missing(), Missing::Nothing),
        "an address the bind named itself cannot go short of an address it never named"
    );
}

/// A drop is asked about as a CLASS, because the case that needs the answer is the one where the
/// instance is gone: the only address on `utun4` expired, so no surviving row carries the link name
/// a question about that one tunnel would have to be phrased in, and a tunnel-only drop would fall
/// through unsaid.
#[test]
fn a_tunnel_whose_only_address_expired_still_answers_for_the_tunnel_class() {
    let dialable = bind_over_drops(
        vec![socket("0.0.0.0", 51979)],
        vec![interface(
            "utun4",
            "100.100.201.59",
            Running::Yes,
            PointToPoint::Yes,
        )],
    );

    assert!(
        report(&dialable).reached(ScopeClass::Tunnel),
        "the class the drop emptied is the one an operator can act on"
    );
    assert!(
        !dialable
            .all()
            .iter()
            .any(|at| at.scope.class() == ScopeClass::Tunnel),
        "no row of that class is left, which is exactly why the question is a class question"
    );
}

/// The set a bind of `bound` comes out with on a host that dropped `dropped` as expiring.
///
/// The surviving interface is fixed and v4, so what a case varies is only the bind and the drops,
/// and it is reached through the seam rather than through the live read: every one of these cases
/// is a dual-stack host with a privacy address on it, which CI is not.
fn bind_over_drops(bound: Vec<SocketAddr>, dropped: Vec<Interface>) -> Dialable {
    Dialable::of_host(
        Ok((
            HostAddrs::of_interfaces(vec![interface(
                "en0",
                "192.168.1.5",
                Running::Yes,
                PointToPoint::No,
            )]),
            Gaps::expiring(dropped),
        )),
        bound,
    )
}

/// One drop in each family, the shape a v4-only bind and a dual-stack bind must read differently:
/// a global v6 address (the RFC 8981 temporary one) and a private v4 address.
fn both_families_dropped() -> Vec<Interface> {
    vec![
        v6("en0", "2605:59c1:18c2:df08:7c65:e101:392a:62b1"),
        interface("en1", "192.168.1.9", Running::Yes, PointToPoint::No),
    ]
}

/// What a set reports it lost to expiry, or a panic naming what it reported instead.
fn report(dialable: &Dialable) -> &Expiring {
    match dialable.missing() {
        Missing::Expiring(dropped) => dropped,
        other => panic!("the bind expands the family these addresses sat in, got {other:?}"),
    }
}

/// What the other two arms must NOT change. Only the interface list is a read the wire depends on:
/// flags this host would not report leave every address in hand, and an address dropped as
/// expiring is one no record may carry anyway, so a record still goes out in both cases.
#[test]
fn only_a_missing_interface_list_takes_this_node_off_the_wire() {
    let bound = vec![socket("0.0.0.0", 51979)];
    for missing in [
        Missing::Flags,
        Missing::Expiring(Expiring::of([Scope::Internet]).expect("one dropped address")),
    ] {
        let dialable = Dialable::short(
            [
                at("192.168.1.5", 51979, Scope::Network),
                at("127.0.0.1", 51979, Scope::ThisMachine),
            ],
            missing,
        );

        let advertising = Advertising::of_dialable(dialable, &bound);

        let Advertising::OnLan(advertised) = advertising else {
            panic!("the network address is still publishable, got {advertising:?}");
        };
        assert_eq!(advertised.addrs(), [socket("192.168.1.5", 51979)]);
    }
}

/// A fixed stand-in for a multi-homed host: two routable v4 addresses, one v6, and loopback in both
/// families, so a test asserts the policy instead of whatever interfaces the machine happens to have.
fn host_addrs() -> HostAddrs {
    HostAddrs(vec![
        host_addr("127.0.0.1", Scope::ThisMachine),
        host_addr("192.168.1.5", Scope::Network),
        host_addr("10.0.0.7", Scope::Network),
        host_addr("::1", Scope::ThisMachine),
        host_addr("2001:db8::5", Scope::Network),
    ])
}

/// Whether a stand-in interface is running, so a test reads as the state it means.
enum Running {
    Yes,
    No,
}

/// Whether a stand-in interface is a point-to-point link, so a test reads as the state it means.
enum PointToPoint {
    Yes,
    No,
}

/// A stand-in for one of this host's interfaces. Only the fields the filter reads carry meaning; the
/// netmask and prefix are whatever a `/24` would be.
fn interface(name: &str, addr: &str, running: Running, p2p: PointToPoint) -> Interface {
    Interface {
        name: name.to_owned(),
        addr: IfAddr::V4(Ifv4Addr {
            ip: addr.parse().expect("a valid IPv4 address"),
            netmask: "255.255.255.0".parse().expect("a valid IPv4 address"),
            prefixlen: 24,
            broadcast: None,
        }),
        index: None,
        // Windows names an adapter as well as an interface; this list is fixed, so the identifier
        // is too.
        #[cfg(windows)]
        adapter_name: "{00000000-0000-0000-0000-000000000000}".to_owned(),
        oper_status: match running {
            Running::Yes => IfOperStatus::Up,
            Running::No => IfOperStatus::Down,
        },
        is_p2p: matches!(p2p, PointToPoint::Yes),
    }
}

/// One of this host's interface addresses, for a fixed host list.
fn host_addr(addr: &str, scope: Scope) -> HostAddr {
    HostAddr {
        ip: ip(addr),
        scope,
    }
}

/// One expanded entry, the way a bind answers on it.
fn at(addr: &str, port: u16, scope: Scope) -> At {
    At {
        socket: socket(addr, port),
        scope,
    }
}

/// A socket address written the way a bind reports it.
fn socket(ip: &str, port: u16) -> SocketAddr {
    format!("{ip}:{port}")
        .parse()
        .expect("a valid socket address")
}

/// A bare IP address for the host's interface list.
fn ip(addr: &str) -> IpAddr {
    addr.parse().expect("a valid IP address")
}

/// THE case the scope split exists for. A unique-local address (`fc00::/7`) reaches this network and
/// stops, exactly like a private v4 address, while a global-unicast address (`2000::/3`) reaches a peer
/// anywhere. Before the split both rendered bare and identically, so four lines of a real banner claimed
/// the widest reach and only two had it. Nothing else here would have caught it: every other case asks
/// where an address came from, and this one asks how far it goes.
#[test]
fn a_unique_local_address_is_not_an_internet_one() {
    let scopes: Vec<Scope> = HostAddrs::of_interfaces(vec![
        v6("en0", "2605:59c1:18c2:df08:1cc1:8f16:93c:5912"),
        v6("en0", "fde2:7482:8f60:8:1cd3:29d9:f098:aa4b"),
        v6("en0", "2001:db8::5"),
        interface("en0", "192.168.1.5", Running::Yes, PointToPoint::No),
        interface("en0", "198.51.100.9", Running::Yes, PointToPoint::No),
    ])
    .0
    .into_iter()
    .map(|addr| addr.scope)
    .collect();

    assert_eq!(
        scopes,
        vec![
            Scope::Internet,
            // Unique-local: this network and no further, whatever it looks like beside the one above.
            Scope::Network,
            // Documentation range, reserved rather than routable, and it sits INSIDE global unicast.
            Scope::Network,
            Scope::Network,
            // The v4 documentation range, for the same reason.
            Scope::Network,
        ],
        "only a genuinely routable address may claim the widest reach"
    );
}

/// Every range here read as [`Scope::Internet`], and not one of them is dialable by a peer on the
/// internet: each is reserved for something smaller than it, or for nothing at all. The live one
/// is `198.18.0.0/15`, which Zscaler, Umbrella and WARP hand out on virtual interfaces that carry
/// no point-to-point flag for the link test to catch.
#[test]
fn a_reserved_range_is_not_an_internet_one() {
    for (addr, reason) in [
        (
            "0.1.2.3",
            "this network, `0.0.0.0/8`, of which only `0.0.0.0` itself was caught",
        ),
        (
            "100.100.201.59",
            "carrier-grade NAT, `100.64.0.0/10`, on a link with no point-to-point flag",
        ),
        ("192.0.0.171", "IETF protocol assignments, `192.0.0.0/24`"),
        ("192.88.99.1", "6to4 relay anycast, `192.88.99.0/24`"),
        ("198.18.0.1", "benchmarking, `198.18.0.0/15`"),
        (
            "198.19.255.254",
            "benchmarking, at the far end of the same /15",
        ),
        ("240.0.0.1", "reserved for future use, `240.0.0.0/4`"),
        (
            "255.255.255.255",
            "broadcast, which `240.0.0.0/4` subsumes and no separate predicate is asked for",
        ),
        (
            "0.0.0.0",
            "unspecified, which `0.0.0.0/8` subsumes for the same reason",
        ),
        ("2001::1", "Teredo, `2001::/32`"),
        ("2001:2::1", "benchmarking, `2001:2::/48`"),
        ("2001:3::1", "AMT, `2001:3::/32`"),
        ("2001:4:112::1", "AS112-v6, `2001:4:112::/48`"),
        ("2001:10::1", "ORCHID, `2001:10::/28`"),
        ("2001:2f:ffff::1", "ORCHIDv2, `2001:20::/28`"),
        (
            "2001:1ff:ffff::1",
            "the far end of IETF protocol assignments, `2001::/23`",
        ),
        (
            "2002:c0a8:105::1",
            "6to4, `2002::/16`, this one derived from `192.168.1.5`",
        ),
        ("3fff::1", "documentation, `3fff::/20`"),
        ("3fff:fff:ffff::1", "the far end of the same /20"),
    ] {
        assert_eq!(scope_of(addr), Scope::Network, "{addr} is {reason}");
    }
}

/// What the tightening above must not swallow. Every range it names is narrow on purpose: an
/// over-refusal costs the only class that reaches a peer who is not already on a network with this
/// host, which is the whole point of naming the class.
#[test]
fn a_routable_address_is_still_an_internet_one() {
    for addr in [
        "1.1.1.1",
        "9.9.9.9",
        "2605:59c1:18c2:df08::5",
        "2606:4700:4700::1111",
        // The first address past the reserved `2001::/23`, which the one arm covering that whole
        // block must not swallow: `2001:200::/23` is an ordinary APNIC allocation.
        "2001:200::1",
        // The first address past documentation's `3fff::/20`.
        "3fff:1000::1",
    ] {
        assert_eq!(
            scope_of(addr),
            Scope::Internet,
            "{addr} is routable from anywhere"
        );
    }
}

/// The scope read off a running, non-point-to-point interface carrying `addr`, whichever family it
/// is in: the shape every range case shares, so a case says its address and its reason and nothing
/// else.
fn scope_of(addr: &str) -> Scope {
    HostAddrs::of_interfaces(vec![match ip(addr) {
        IpAddr::V4(_) => interface("en0", addr, Running::Yes, PointToPoint::No),
        IpAddr::V6(_) => v6("en0", addr),
    }])
    .0
    .into_iter()
    .next()
    .map(|host| host.scope)
    .expect("a running interface that is not link-local is kept")
}

/// A tunnel address is classified by its LINK, never by its prefix, and the two disagree on purpose: a
/// tailnet hands out carrier-grade NAT space, which is neither private nor globally routable, so a
/// prefix test alone would have to guess. The link is the better evidence and it is asked first.
#[test]
fn a_tunnel_address_is_classified_by_its_link_not_its_prefix() {
    let host = HostAddrs::of_interfaces(vec![interface(
        "utun4",
        "100.100.201.59",
        Running::Yes,
        PointToPoint::Yes,
    )]);

    assert_eq!(
        host.0.first().map(|addr| addr.scope.clone()),
        Some(Scope::Tunnel {
            link: "utun4".to_owned()
        }),
        "the link says who can route to it; the prefix does not"
    );
}

/// The one test that takes the real syscall path, so the platform read is exercised rather than
/// only parsed.
///
/// Every other test here drives `of_interfaces` with a fixture, which is what keeps them
/// host-independent -- but it also means the netlink dump and the `SIOCGIFAFLAG_IN6` ioctl are
/// reachable in production and by nothing in CI. This asserts only what is true of every host:
/// the set is never empty, loopback is in it, loopback sorts last, and no link-local survives.
/// A host's actual addresses are its own business and are not asserted.
#[test]
fn the_real_host_expands_into_a_set_that_ends_at_loopback() {
    let dialable = Dialable::of(vec![
        "0.0.0.0:0".parse().expect("a valid v4 wildcard"),
        "[::]:0".parse().expect("a valid v6 wildcard"),
    ]);
    let all = dialable.all();

    assert!(
        !all.is_empty(),
        "a wildcard bind answers at loopback at the very least"
    );
    assert!(
        all.iter().any(|at| at.socket.ip().is_loopback()),
        "a wildcard bind answers on loopback, whatever else this host has"
    );
    assert!(
        all.last()
            .expect("the set is not empty")
            .socket
            .ip()
            .is_loopback(),
        "loopback sorts last, so the lane never leads with the one address that works \
         only for a peer already on this machine"
    );
    // Spelled out rather than reusing the crate's own predicate: a test that shares the
    // implementation's definition of link-local cannot catch that definition being wrong.
    assert!(
        all.iter().all(|at| match at.socket.ip() {
            IpAddr::V4(v4) => !v4.is_link_local(),
            IpAddr::V6(v6) => v6.segments()[0] & 0xffc0 != 0xfe80,
        }),
        "a link-local address means nothing without its interface scope, so it is filtered"
    );
}

/// An IPv6 stand-in interface, since the shared constructor builds v4 only and the scope split is
/// mostly a v6 question.
fn v6(name: &str, addr: &str) -> Interface {
    Interface {
        name: name.to_owned(),
        addr: IfAddr::V6(if_addrs::Ifv6Addr {
            ip: addr.parse().expect("a valid IPv6 address"),
            netmask: "ffff:ffff:ffff:ffff::"
                .parse()
                .expect("a valid IPv6 address"),
            prefixlen: 64,
            broadcast: None,
        }),
        index: None,
        // Windows names an adapter as well as an interface; this list is fixed, so the identifier
        // is too.
        #[cfg(windows)]
        adapter_name: "{00000000-0000-0000-0000-000000000000}".to_owned(),
        oper_status: IfOperStatus::Up,
        is_p2p: false,
    }
}
