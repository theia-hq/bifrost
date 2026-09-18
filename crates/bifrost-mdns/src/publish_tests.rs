//! Publication policy over a fixed input: which of the addresses a bind answers on may be published,
//! which port the record names, and what the result reaches.
//!
//! The expansion these run on top of is [`crate::host`]'s, and its own cases (including which
//! entries this policy then keeps) live in `host_tests.rs`.

use core::net::{Ipv4Addr, SocketAddr};

use crate::MdnsError;
use crate::publish::{Advertised, Advertising};

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

/// The published set and the multicast egress pin come from one set, so this node never hands a peer
/// an address it does not send queries from. The pin is the IPv4 half, the only family the egress
/// leg uses.
#[test]
fn the_egress_pin_is_the_published_sets_own_v4_half() {
    let advertising = Advertising::of_publishable(vec![
        socket("192.168.1.5", 51979),
        socket("10.0.0.7", 51979),
        socket("[::1]", 51979),
    ]);
    let advertised = advertising.advertised().expect("a routable address");

    assert_eq!(
        advertised.addrs(),
        [
            socket("192.168.1.5", 51979),
            socket("10.0.0.7", 51979),
            socket("[::1]", 51979)
        ],
        "the published set is what was handed over, in order"
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

/// A socket address written the way a bind reports it.
fn socket(ip: &str, port: u16) -> SocketAddr {
    format!("{ip}:{port}")
        .parse()
        .expect("a valid socket address")
}

/// A bare IPv4 address, for the egress pin.
fn v4(addr: &str) -> Ipv4Addr {
    addr.parse().expect("a valid IPv4 address")
}
