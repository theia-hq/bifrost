//! The seam between what a platform reports and this host's own list: which interface a reported
//! address belongs to. Pure, so it runs on every target, including the ones with no port of the
//! flag read at all.

use core::net::Ipv6Addr;

use if_addrs::{IfAddr, IfOperStatus, Ifv6Addr, Interface};

use super::split;

/// Why each port returns the LINK and not only the address: the same address can sit on two
/// interfaces, and only the one the kernel flagged is on its way out. Matching on the address
/// alone would take a durable address off the other link with it.
#[test]
fn an_address_reported_on_one_link_is_dropped_only_from_that_link() {
    let shared = addr("2605:59c1:18c2:df08:7c65:e101:392a:62b1");

    let (stable, dropped) = split(
        vec![v6("en0", shared), v6("utun4", shared)],
        &[("en0".to_owned(), shared)],
    );

    assert_eq!(links(&stable), ["utun4"]);
    assert_eq!(links(&dropped), ["en0"]);
}

/// Nothing reported drops nothing, which is the shape every failed read degrades into: the whole
/// list survives a platform that answered with an empty hand.
#[test]
fn an_empty_report_keeps_every_address() {
    let (stable, dropped) = split(
        vec![
            v6("en0", addr("2605:59c1:18c2:df08::5")),
            v6("lo0", addr("::1")),
        ],
        &[],
    );

    assert_eq!(links(&stable), ["en0", "lo0"]);
    assert!(dropped.is_empty());
}

/// The interface names of a list, which is the whole of what these cases assert.
fn links(interfaces: &[Interface]) -> Vec<&str> {
    interfaces
        .iter()
        .map(|interface| interface.name.as_str())
        .collect()
}

/// One of this host's IPv6 interfaces. Only the name and the address carry meaning here; the
/// netmask is whatever a `/64` would be.
fn v6(name: &str, ip: Ipv6Addr) -> Interface {
    Interface {
        name: name.to_owned(),
        addr: IfAddr::V6(Ifv6Addr {
            ip,
            netmask: addr("ffff:ffff:ffff:ffff::"),
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

/// An address written the way an interface list reports it.
fn addr(text: &str) -> Ipv6Addr {
    text.parse().expect("a valid IPv6 address")
}
