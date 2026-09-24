//! What a serving node puts on the wire, read off the wire.
//!
//! Its own test binary, so the node it starts never shares the LAN with the in-crate multicast
//! tests: cargo runs test binaries one after another, and one more node answering on the loopback
//! interface slows the others' first answers past their settle window.
//!
//! It drives real multicast, so it is `#[ignore]`d by default like the in-crate multicast tests. Run
//! it locally with `cargo test -p bifrost-mdns -- --ignored`.

use core::net::{IpAddr, Ipv4Addr, SocketAddr};
use core::time::Duration;
use std::io;
use std::net::UdpSocket;

use bifrost_core::{CryptoKind, NodeId};
use bifrost_mdns::MdnsDiscovery;
use socket2::{Domain, Protocol, Socket, Type};

/// No record a serving node puts on the wire carries its key: not the instance name, not the SRV
/// target host `<name>-<port>.local.` the dependency derives from it, not a TXT record. A raw
/// listener on the mDNS port reads every packet on the loopback interface the node announces on and
/// looks for the key's text, its base32 body and its raw bytes.
#[tokio::test]
#[ignore = "drives real multicast; run locally with --ignored"]
async fn no_record_carries_the_key() {
    let listener = listen().expect("listen on the mDNS group");
    let serving = NodeId::new(CryptoKind::Ed25519, [90; NodeId::KEY_LEN]);
    let port = 4090;
    let _mdns = MdnsDiscovery::advertise(serving, [addr(port)])
        .expect("advertises")
        .discovery;

    let packets = tokio::task::spawn_blocking(move || read_for(&listener, Duration::from_secs(5)))
        .await
        .expect("the listener ran");

    let host = format!("-{port}");
    assert!(
        packets
            .iter()
            .any(|packet| contains(packet, b"_bifrost") && contains(packet, host.as_bytes())),
        "the node's own answer, with its SRV target host, was read off the wire"
    );
    let key = serving.to_string();
    let body = &key[4..];
    for packet in &packets {
        let text = packet.to_ascii_lowercase();
        assert!(!contains(&text, key.as_bytes()), "a record carries {key}");
        assert!(!contains(&text, body.as_bytes()), "a record carries {body}");
        assert!(
            !contains(packet, &[90; NodeId::KEY_LEN]),
            "a record carries the raw key"
        );
    }
}

/// A socket reading everything sent to the mDNS group on the loopback interface, beside every
/// other reader of that port.
///
/// Bound to the group address, not the wildcard, so it reads only what is multicast: a unicast
/// answer to this port is delivered to one socket alone, and this one must never take it from the
/// node under test or the system's own responder.
fn listen() -> io::Result<UdpSocket> {
    let group = Ipv4Addr::new(224, 0, 0, 251);
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_reuse_address(true)?;
    socket.set_reuse_port(true)?;
    socket.bind(&SocketAddr::new(IpAddr::V4(group), 5353).into())?;
    socket.join_multicast_v4(&group, &Ipv4Addr::LOCALHOST)?;
    socket.set_read_timeout(Some(Duration::from_millis(100)))?;
    Ok(socket.into())
}

/// Every packet `socket` reads within `span`.
fn read_for(socket: &UdpSocket, span: Duration) -> Vec<Vec<u8>> {
    let deadline = std::time::Instant::now() + span;
    let mut packets = Vec::new();
    let mut buf = [0; 9000];
    while std::time::Instant::now() < deadline {
        if let Ok(len) = socket.recv(&mut buf) {
            packets.push(buf[..len].to_vec());
        }
    }
    packets
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

/// A loopback socket address on the given port.
fn addr(port: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)
}
