//! The expansion itself: which sockets a bind answers on, how far each of them reaches, and what
//! survives an interface list the host will not hand over.
//!
//! Enumeration runs against a handed [`HostAddrs`] rather than the machine's real interfaces, so
//! these assert the policy itself and hold on any host, CI included.

use core::net::{IpAddr, SocketAddr};
use std::io;

use if_addrs::{IfAddr, IfOperStatus, Ifv4Addr, Interface};

use crate::MdnsError;
use crate::host::{At, Dialable, HostAddr, HostAddrs, Reach};
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
            at("192.168.1.5", 51979, Reach::Network),
            at("10.0.0.7", 51979, Reach::Network),
            at("127.0.0.1", 51979, Reach::ThisMachine),
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
        vec![at("127.0.0.1", 9000, Reach::ThisMachine)]
    );
    assert_eq!(
        host.expand(vec![socket("192.168.1.5", 9000)]),
        vec![at("192.168.1.5", 9000, Reach::Network)]
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
            at("[2001:db8::5]", 51987, Reach::Network),
            at("[::1]", 51987, Reach::ThisMachine),
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
            at("192.168.1.5", 4000, Reach::Network),
            at("10.0.0.7", 4000, Reach::Network),
            at("127.0.0.1", 4000, Reach::ThisMachine),
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
            at("192.168.1.5", 50663, Reach::Network),
            at(
                "100.100.201.59",
                50663,
                Reach::Tunnel {
                    link: "utun4".to_owned()
                }
            ),
            at("127.0.0.1", 50663, Reach::ThisMachine),
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

    let advertising = Advertising::of_dialable(Dialable::of_host(Ok(host), bound.clone()), &bound);

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
            at("192.168.1.5", 51979, Reach::Network),
            at("127.0.0.1", 51979, Reach::ThisMachine),
        ]
    );
}

/// The link-local guard holds on the address list too, so a `fe80::` cannot reach a consumer even if
/// the interface list it came from was assembled some other way.
#[test]
fn a_link_local_address_is_never_yielded() {
    let host = HostAddrs(vec![
        host_addr("fe80::1", Reach::Network),
        host_addr("2001:db8::5", Reach::Network),
    ]);

    assert_eq!(
        host.expand(vec![socket("[::]", 51987)]),
        vec![
            at("[2001:db8::5]", 51987, Reach::Network),
            at("[::1]", 51987, Reach::ThisMachine),
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
    let dialable = Dialable::of_host(Ok(HostAddrs(Vec::new())), bound.clone());

    assert_eq!(
        dialable.all(),
        [at("127.0.0.1", 51979, Reach::ThisMachine)],
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
    let failed = Err(MdnsError::Interfaces(io::Error::other(
        "no interfaces here",
    )));

    let dialable = Dialable::of_host(failed, bound.clone());

    assert_eq!(
        dialable.all(),
        [
            at("127.0.0.1", 51979, Reach::ThisMachine),
            at("127.0.0.1", 9000, Reach::ThisMachine),
        ],
        "the wildcard's loopback and the concrete bind survive a read that failed"
    );
    assert!(
        matches!(dialable.interfaces(), Some(MdnsError::Interfaces(_))),
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

/// A fixed stand-in for a multi-homed host: two routable v4 addresses, one v6, and loopback in both
/// families, so a test asserts the policy instead of whatever interfaces the machine happens to have.
fn host_addrs() -> HostAddrs {
    HostAddrs(vec![
        host_addr("127.0.0.1", Reach::ThisMachine),
        host_addr("192.168.1.5", Reach::Network),
        host_addr("10.0.0.7", Reach::Network),
        host_addr("::1", Reach::ThisMachine),
        host_addr("2001:db8::5", Reach::Network),
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
        oper_status: match running {
            Running::Yes => IfOperStatus::Up,
            Running::No => IfOperStatus::Down,
        },
        is_p2p: matches!(p2p, PointToPoint::Yes),
    }
}

/// One of this host's interface addresses, for a fixed host list.
fn host_addr(addr: &str, reach: Reach) -> HostAddr {
    HostAddr {
        ip: ip(addr),
        reach,
    }
}

/// One expanded entry, the way a bind answers on it.
fn at(addr: &str, port: u16, reach: Reach) -> At {
    At {
        socket: socket(addr, port),
        reach,
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

/// THE case the reach split exists for. A unique-local address (`fc00::/7`) reaches this network and
/// stops, exactly like a private v4 address, while a global-unicast address (`2000::/3`) reaches a peer
/// anywhere. Before the split both rendered bare and identically, so four lines of a real banner claimed
/// the widest reach and only two had it. Nothing else here would have caught it: every other case asks
/// where an address came from, and this one asks how far it goes.
#[test]
fn a_unique_local_address_is_not_an_internet_one() {
    let reaches: Vec<Reach> = HostAddrs::of_interfaces(vec![
        v6("en0", "2605:59c1:18c2:df08:1cc1:8f16:93c:5912"),
        v6("en0", "fde2:7482:8f60:8:1cd3:29d9:f098:aa4b"),
        v6("en0", "2001:db8::5"),
        interface("en0", "192.168.1.5", Running::Yes, PointToPoint::No),
        interface("en0", "198.51.100.9", Running::Yes, PointToPoint::No),
    ])
    .0
    .into_iter()
    .map(|addr| addr.reach)
    .collect();

    assert_eq!(
        reaches,
        vec![
            Reach::Internet,
            // Unique-local: this network and no further, whatever it looks like beside the one above.
            Reach::Network,
            // Documentation range, reserved rather than routable, and it sits INSIDE global unicast.
            Reach::Network,
            Reach::Network,
            // The v4 documentation range, for the same reason.
            Reach::Network,
        ],
        "only a genuinely routable address may claim the widest reach"
    );
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
        host.0.first().map(|addr| addr.reach.clone()),
        Some(Reach::Tunnel {
            link: "utun4".to_owned()
        }),
        "the link says who can route to it; the prefix does not"
    );
}

/// An IPv6 stand-in interface, since the shared constructor builds v4 only and the reach split is
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
        oper_status: IfOperStatus::Up,
        is_p2p: false,
    }
}
