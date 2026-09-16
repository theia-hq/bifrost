//! Publication policy over a fixed input: which addresses a bind set yields, which port the record
//! names, and what the result reaches.
//!
//! Enumeration runs against a handed [`HostAddrs`] rather than the machine's real interfaces, so
//! these assert the policy itself and hold on any host, CI included.

use core::net::{IpAddr, Ipv4Addr, SocketAddr};

use if_addrs::{IfAddr, IfOperStatus, Ifv4Addr, Interface};

use crate::MdnsError;
use crate::publish::{Advertised, Advertising, HostAddrs};

/// A wildcard bind means "every interface", so it expands into this host's concrete addresses on the
/// bound port. Loopback is left out: a peer that heard `127.0.0.1` would dial its own machine, so a
/// wildcard must never put it on the wire.
#[test]
fn a_wildcard_expands_into_the_hosts_non_loopback_addresses() {
    let host = host_addrs();

    let publishable = host.expand(vec![socket("0.0.0.0", 51979)]);

    assert_eq!(
        publishable,
        vec![socket("192.168.1.5", 51979), socket("10.0.0.7", 51979)],
        "the wildcard stands for the host's non-loopback v4 addresses, on the bound port"
    );
}

/// A concrete loopback bind is published as itself and never expanded: the caller bound a host-local
/// service, and expanding it into LAN addresses would publish a reach it deliberately did not bind.
#[test]
fn a_loopback_bind_publishes_exactly_itself() {
    let host = host_addrs();

    let publishable = host.expand(vec![socket("127.0.0.1", 9000)]);

    assert_eq!(publishable, vec![socket("127.0.0.1", 9000)]);
}

/// A v4 wildcard takes the host's v4 addresses and a v6 wildcard its v6 ones. Crossing families
/// would name an address on a socket that never bound it.
#[test]
fn a_wildcard_expands_within_its_own_family() {
    let host = host_addrs();

    let publishable = host.expand(vec![socket("[::]", 51987)]);

    assert_eq!(publishable, vec![socket("[2001:db8::5]", 51987)]);
}

/// Two wildcards on one port describe the same interfaces, and a duplicate address would be
/// published and pinned twice for no gain.
#[test]
fn an_expansion_publishes_each_address_once() {
    let host = host_addrs();

    let publishable = host.expand(vec![socket("0.0.0.0", 4000), socket("0.0.0.0", 4000)]);

    assert_eq!(
        publishable,
        vec![socket("192.168.1.5", 4000), socket("10.0.0.7", 4000)]
    );
}

/// Only an interface a peer could actually reach this node over is advertised. A link that is not
/// running is a timeout for the dialer; a point-to-point link (utun, tun, wg, a tailnet) has no LAN
/// behind it and would take a dial that follows the first hint; a link-local address is unusable
/// without a scope no record carries.
#[test]
fn only_reachable_interfaces_are_advertised() {
    let host = HostAddrs::of_interfaces(vec![
        interface("en0", "192.168.1.5", Running::Yes, PointToPoint::No),
        interface("en1", "192.168.2.5", Running::No, PointToPoint::No),
        interface("utun3", "100.100.201.59", Running::Yes, PointToPoint::Yes),
        interface("en2", "169.254.11.4", Running::Yes, PointToPoint::No),
    ]);

    assert_eq!(
        host.expand(vec![socket("0.0.0.0", 51979)]),
        vec![socket("192.168.1.5", 51979)],
        "the down link, the point-to-point link, and the link-local address are all left out"
    );
}

/// The link-local guard holds on the address list too, so a `fe80::` cannot reach a record even if
/// the interface list it came from was assembled some other way.
#[test]
fn a_link_local_address_is_never_published() {
    let host = HostAddrs(vec![ip("fe80::1"), ip("2001:db8::5")]);

    assert_eq!(
        host.expand(vec![socket("[::]", 51987)]),
        vec![socket("[2001:db8::5]", 51987)]
    );
}

/// A published set with a non-loopback address in it reaches other hosts, which is the only state
/// that lets a surface claim LAN discovery.
#[test]
fn a_routable_address_advertises_on_the_lan() {
    let advertising = Advertising::of_publishable(vec![socket("192.168.1.5", 51979)]);

    let Advertising::OnLan(advertised) = advertising else {
        panic!("a routable address reaches the LAN, got {advertising:?}");
    };
    assert_eq!(advertised.addrs(), [socket("192.168.1.5", 51979)]);
}

/// An all-loopback set is advertised (another process on this machine finds it) and reaches no other
/// host, so it reads down with its own named state rather than passing for a LAN advertisement.
#[test]
fn an_all_loopback_set_advertises_loopback_only() {
    let advertising =
        Advertising::of_publishable(vec![socket("127.0.0.1", 9000), socket("[::1]", 9000)]);

    let Advertising::LoopbackOnly(advertised) = advertising else {
        panic!("loopback reaches nothing off this host, got {advertising:?}");
    };
    assert_eq!(
        advertised.addrs(),
        [socket("127.0.0.1", 9000), socket("[::1]", 9000)]
    );
}

/// Nothing to advertise leaves the node BROWSING, not disabled: it still hears every peer on the
/// LAN, and the cause of the silence is named.
#[test]
fn an_empty_bind_set_browses_only() {
    let advertising = Advertising::of_publishable(Vec::new());

    assert!(matches!(
        advertising,
        Advertising::BrowseOnly(MdnsError::NoAddrs)
    ));
    assert!(
        advertising.advertised().is_none(),
        "a browse-only node publishes no record"
    );
}

/// A wildcard on a host with no non-loopback address expands into nothing, which is browse-only for
/// the same reason an empty bind is: there is no address a peer could dial.
#[test]
fn a_wildcard_on_an_isolated_host_browses_only() {
    let host = HostAddrs(vec![ip("127.0.0.1")]);

    let advertising = Advertising::of_publishable(host.expand(vec![socket("0.0.0.0", 51979)]));

    assert!(matches!(
        advertising,
        Advertising::BrowseOnly(MdnsError::NoAddrs)
    ));
}

/// The published set and the multicast egress pin come from one set, so this node never hands a peer
/// an address it does not send queries from. The pin is the IPv4 half, the only family the egress
/// leg uses.
#[test]
fn the_egress_pin_is_the_published_sets_own_v4_half() {
    let host = host_addrs();

    let publishable = host.expand(vec![socket("0.0.0.0", 51979), socket("[::1]", 51979)]);
    let advertising = Advertising::of_publishable(publishable);
    let advertised = advertising.advertised().expect("a routable address");

    assert_eq!(
        advertised.addrs(),
        [
            socket("192.168.1.5", 51979),
            socket("10.0.0.7", 51979),
            socket("[::1]", 51979)
        ],
        "the published set is the expanded bind set"
    );
    assert_eq!(
        advertised.egress_v4(),
        vec![v4("192.168.1.5"), v4("10.0.0.7")],
        "the pin is the published set's own v4 addresses, in the same order"
    );
}

/// A multi-port bind (iroh binds a v4 and a v6 socket on different ephemeral ports) cannot be
/// advertised whole, so it advertises the port of the v4 socket: the address a peer dials. The v6
/// socket on another port is left out, never folded into a port that cannot carry it.
#[test]
fn a_multi_port_bind_advertises_the_v4_sockets_port() {
    let v4: SocketAddr = "127.0.0.1:51979".parse().expect("a valid v4 address");
    let v6: SocketAddr = "[::1]:51987".parse().expect("a valid v6 address");

    let advertised = Advertised::of([v4, v6]).expect("the v4 socket makes the bind advertisable");
    assert_eq!(
        advertised.port(),
        51979,
        "the chosen port is the v4 socket's"
    );
    assert_eq!(
        advertised.addrs(),
        [v4],
        "only the addresses on the chosen port are advertised"
    );

    // A v6 socket that SHARES the chosen port rides along: the advertisement is the whole port group,
    // not merely the v4 socket.
    let v6_twin: SocketAddr = "[::1]:51979".parse().expect("a valid v6 address");
    let advertised =
        Advertised::of([v4, v6, v6_twin]).expect("the shared v4 port makes the bind advertisable");
    assert_eq!(advertised.port(), 51979);
    assert_eq!(advertised.addrs(), [v4, v6_twin]);
}

/// The single-port path is unchanged: one listener across interfaces is one port plus every bound
/// address, whatever family, and the multi-port preference never narrows it.
#[test]
fn a_single_port_bind_advertises_every_address() {
    let v4: SocketAddr = "127.0.0.1:51979".parse().expect("a valid v4 address");
    let v6: SocketAddr = "[::1]:51979".parse().expect("a valid v6 address");

    let advertised = Advertised::of([v4, v6]).expect("a shared port is advertisable");
    assert_eq!(advertised.port(), 51979);
    assert_eq!(advertised.addrs(), [v4, v6]);

    // A v6-only single-port bind keeps its prior behavior too.
    let advertised = Advertised::of([v6]).expect("a single v6 port is advertisable");
    assert_eq!(advertised.port(), 51979);
    assert_eq!(advertised.addrs(), [v6]);
}

/// A multi-port bind with no IPv4 socket has nothing a peer on the v4 query path could dial: a named
/// error, never a partial or guessed advertisement.
#[test]
fn a_multi_port_bind_without_a_v4_socket_is_an_error() {
    let v6: SocketAddr = "[::1]:1000".parse().expect("a valid v6 address");
    let v6_other: SocketAddr = "[::2]:2000".parse().expect("a valid v6 address");

    assert!(matches!(
        Advertised::of([v6, v6_other]),
        Err(MdnsError::NoV4Addrs)
    ));
}

/// No addresses at all is the named error, not a panic on the empty set.
#[test]
fn an_empty_bind_is_an_error() {
    assert!(matches!(Advertised::of([]), Err(MdnsError::NoAddrs)));
}

/// A fixed stand-in for a multi-homed host: two routable v4 addresses, one v6, and loopback in both
/// families, so a test asserts the policy instead of whatever interfaces the machine happens to have.
fn host_addrs() -> HostAddrs {
    HostAddrs(vec![
        ip("127.0.0.1"),
        ip("192.168.1.5"),
        ip("10.0.0.7"),
        ip("::1"),
        ip("2001:db8::5"),
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
            netmask: v4("255.255.255.0"),
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

/// A bare IPv4 address, for the egress pin.
fn v4(addr: &str) -> Ipv4Addr {
    addr.parse().expect("a valid IPv4 address")
}
