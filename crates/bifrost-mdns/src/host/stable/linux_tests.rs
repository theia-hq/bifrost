//! The netlink dump's parse, over fixtures rather than over whatever addresses the running kernel
//! happens to have: the walk is the half of this that can be wrong on any host, so it is the half
//! that is pinned here.
//!
//! Two kinds of case. The first is what the kernel sends: a permanent address beside a temporary
//! one, the full-width flags attribute, the odd-length attribute a modern kernel pads. The second
//! is what it must never be able to send: a length that does not fit the bytes behind it. Each
//! guard in the walk has a case here that FAILS with the guard deleted, because a guard's test
//! that passes without it is worth nothing.

use core::net::Ipv6Addr;

use if_addrs::{IfAddr, IfOperStatus, Ifv6Addr, Interface};

use super::{Flow, NLMSGHDR, RTATTR, link_of, scan};

/// An interface's stable address and the RFC 8981 temporary one beside it: the pair the whole
/// mechanism exists to tell apart, and by their bits alone nothing can.
#[test]
fn a_temporary_address_is_reported_and_a_permanent_one_is_not() {
    let stable = addr("2605:59c1:18c2:df08::5");
    let temporary = addr("2605:59c1:18c2:df08:7c65:e101:392a:62b1");
    let mut datagram = announcement(stable, libc::IFA_F_PERMANENT, None);
    datagram.extend(announcement(temporary, libc::IFA_F_TEMPORARY, None));

    let mut expiring = Vec::new();

    assert!(matches!(scan(&datagram, &mut expiring), Flow::More));
    assert_eq!(expiring, vec![(LINK, temporary)]);
}

/// A deprecated address is on its way out at the end of its preferred lifetime, so it is dropped
/// for the same reason a temporary one is: it rots in the hand of the peer it was given to.
#[test]
fn a_deprecated_address_is_reported() {
    let deprecated = addr("2605:59c1:18c2:df08::5");
    let datagram = announcement(deprecated, libc::IFA_F_DEPRECATED, None);

    let mut expiring = Vec::new();
    scan(&datagram, &mut expiring);

    assert_eq!(expiring, vec![(LINK, deprecated)]);
}

/// The header carries eight bits of a field that is thirty-two wide, and a kernel with anything
/// above the byte repeats the whole field in an attribute. The attribute is the one to believe.
#[test]
fn the_full_width_flags_attribute_wins_over_the_truncated_byte() {
    let deprecated = addr("2605:59c1:18c2:df08::5");
    let datagram = announcement(deprecated, 0, Some(libc::IFA_F_DEPRECATED));

    let mut expiring = Vec::new();
    scan(&datagram, &mut expiring);

    assert_eq!(expiring, vec![(LINK, deprecated)]);
}

/// The kernel ends a dump with `NLMSG_DONE`, and the receive loop has to stop on it: without that
/// it blocks until the socket's own timeout on every single read.
#[test]
fn the_end_of_the_dump_stops_the_receive() {
    let mut expiring = Vec::new();

    assert!(matches!(
        scan(&message(libc::NLMSG_DONE as u16, &[]), &mut expiring),
        Flow::Done
    ));
}

/// A datagram longer than the buffer arrives cut, and a cut message must read as no message at
/// all. Keeping an address whose flags were not read is the safe direction; inventing one from a
/// half-read attribute is not.
///
/// This is the bound on the MESSAGE against the datagram behind it. It is not the attribute
/// bound: a cut here trips the outer guard first, which is why the two below exist.
#[test]
fn a_cut_message_is_not_read_as_a_whole_one() {
    let temporary = addr("2605:59c1:18c2:df08:7c65:e101:392a:62b1");
    let datagram = announcement(temporary, libc::IFA_F_TEMPORARY, None);

    for cut in 0..datagram.len() {
        let mut expiring = Vec::new();
        scan(&datagram[..cut], &mut expiring);
        assert!(
            expiring.is_empty(),
            "a message cut at {cut} of {} bytes was read as a whole one",
            datagram.len()
        );
    }
}

/// A message shorter than its own header names a payload that is not there, and the walk would
/// read it backwards. The whole datagram is intact, so nothing else catches this.
#[test]
fn a_message_shorter_than_its_own_header_ends_the_walk() {
    let mut datagram = announcement(addr("2605:59c1:18c2:df08::5"), libc::IFA_F_TEMPORARY, None);
    datagram[0..4].copy_from_slice(&8u32.to_ne_bytes());

    let mut expiring = Vec::new();

    assert!(matches!(scan(&datagram, &mut expiring), Flow::Done));
    assert!(expiring.is_empty(), "there is no whole message to read");
}

/// An attribute shorter than its own header is the classic netlink spin: the walk advances by the
/// length it was handed, and a length under four advances by nothing at all. The message is
/// well-formed around it, so the message bound never sees this one.
#[test]
fn an_attribute_shorter_than_its_own_header_ends_the_attribute_walk() {
    let datagram = announced(
        libc::IFA_F_TEMPORARY,
        &[
            attribute(libc::IFA_ADDRESS, &addr("2605:59c1:18c2:df08::5").octets()),
            attribute_of_length(0),
        ],
    );

    let mut expiring = Vec::new();
    scan(&datagram, &mut expiring);

    assert_eq!(
        expiring,
        vec![(LINK, addr("2605:59c1:18c2:df08::5"))],
        "the walk ends at the malformed attribute and the message is judged on what was read"
    );
}

/// An attribute claiming more bytes than the message holds is the other half of the same guard,
/// and the one that would read past the message into whatever is behind it.
#[test]
fn an_attribute_longer_than_its_message_ends_the_attribute_walk() {
    let datagram = announced(
        libc::IFA_F_TEMPORARY,
        &[
            attribute_of_length(64),
            attribute(libc::IFA_ADDRESS, &addr("2605:59c1:18c2:df08::5").octets()),
        ],
    );

    let mut expiring = Vec::new();
    scan(&datagram, &mut expiring);

    assert!(
        expiring.is_empty(),
        "the walk ends before the address, so there is no address to report"
    );
}

/// Only the kernel may say an address is expiring, and a netlink message names its sender: the
/// kernel's port id is zero and nobody else's is. Unreachable in practice, and the check is what
/// makes that this parse's own boundary rather than one inherited from a registration flag.
#[test]
fn a_message_from_anything_but_the_kernel_is_not_read() {
    let temporary = addr("2605:59c1:18c2:df08:7c65:e101:392a:62b1");
    let mut datagram = announcement(temporary, libc::IFA_F_TEMPORARY, None);
    datagram[12..16].copy_from_slice(&4242u32.to_ne_bytes());

    let mut expiring = Vec::new();
    scan(&datagram, &mut expiring);

    assert!(
        expiring.is_empty(),
        "a message from another port id says nothing about this host's addresses"
    );
}

/// The real wire, which no fixture above is: Linux >= 6.4 sends `IFA_PROTO`, one byte of value at
/// `rta_len` 5, and the attribute behind it starts three bytes later. A message whose last
/// attribute is odd-length is itself unaligned, and the next message starts at the boundary past
/// it. Get either padding wrong and `IFA_FLAGS` is read off the wrong bytes, which is the one
/// attribute that decides the drop.
#[test]
fn padding_between_attributes_and_between_messages_does_not_shift_the_walk() {
    let stable = addr("2605:59c1:18c2:df08::5");
    let temporary = addr("2605:59c1:18c2:df08:7c65:e101:392a:62b1");
    let mut datagram = announced(
        0,
        &[
            attribute(libc::IFA_ADDRESS, &stable.octets()),
            attribute(IFA_PROTO, &[libc::RTPROT_KERNEL]),
            attribute(libc::IFA_FLAGS, &libc::IFA_F_PERMANENT.to_ne_bytes()),
            // The kernel does not pad the last attribute of a message; `NLMSG_ALIGN` covers the
            // gap to the next one, which is what the append below writes.
            unpadded(libc::IFA_LABEL, b"wlan0\0"),
        ],
    );
    append(
        &mut datagram,
        &announcement(temporary, 0, Some(libc::IFA_F_TEMPORARY)),
    );

    let mut expiring = Vec::new();
    scan(&datagram, &mut expiring);

    assert_eq!(
        expiring,
        vec![(LINK, temporary)],
        "the padded permanent address is kept and the message behind the unaligned one is still read"
    );
}

/// The dump answers per interface index and the caller matches on the link, so an index this host
/// did not report has no link to name. Dropping it keeps the address: naming it wrongly would
/// drop a durable address off some other interface.
#[test]
fn an_index_this_host_did_not_report_names_no_link() {
    let interfaces = [interface("en0", 3), interface("utun4", 11)];

    assert_eq!(link_of(&interfaces, 11), Some("utun4"));
    assert_eq!(link_of(&interfaces, 7), None);
}

/// `IFA_PROTO`, which Linux >= 6.4 emits and `libc` does not name yet.
const IFA_PROTO: u16 = 11;

/// The interface index every fixture announces on, and the one the kept pair carries.
const LINK: u32 = 1;

/// One `RTM_NEWADDR` as the kernel puts it on the socket: an `ifaddrmsg`, the address as an
/// `IFA_ADDRESS` attribute, and the full-width flags as an `IFA_FLAGS` one where `full` says the
/// kernel sends them.
fn announcement(addr: Ipv6Addr, flags: u32, full: Option<u32>) -> Vec<u8> {
    let mut attributes = vec![attribute(libc::IFA_ADDRESS, &addr.octets())];
    if let Some(full) = full {
        attributes.push(attribute(libc::IFA_FLAGS, &full.to_ne_bytes()));
    }
    announced(flags, &attributes)
}

/// One `RTM_NEWADDR` carrying exactly the attributes given, for the cases that are about the
/// attributes themselves.
fn announced(flags: u32, attributes: &[Vec<u8>]) -> Vec<u8> {
    let mut body = vec![
        libc::AF_INET6 as u8,
        64,
        u8::try_from(flags & 0xff).unwrap_or_default(),
        0,
    ];
    body.extend_from_slice(&LINK.to_ne_bytes());
    for attribute in attributes {
        body.extend_from_slice(attribute);
    }
    message(libc::RTM_NEWADDR, &body)
}

/// One netlink message: the header, then the body it announces.
fn message(kind: u16, body: &[u8]) -> Vec<u8> {
    let mut message = Vec::with_capacity(NLMSGHDR + body.len());
    message.extend_from_slice(&((NLMSGHDR + body.len()) as u32).to_ne_bytes());
    message.extend_from_slice(&kind.to_ne_bytes());
    // Flags and sequence, neither of which the parse reads, then the sender's port id, which is
    // zero for the kernel and is read.
    message.extend_from_slice(&[0u8; 10]);
    message.extend_from_slice(body);
    message
}

/// Append `message` at the four-byte boundary the kernel starts every message on.
fn append(datagram: &mut Vec<u8>, message: &[u8]) {
    datagram.resize(datagram.len().next_multiple_of(4), 0);
    datagram.extend_from_slice(message);
}

/// One netlink attribute, padded to where the next one starts.
fn attribute(kind: u16, value: &[u8]) -> Vec<u8> {
    let mut attribute = unpadded(kind, value);
    attribute.resize(attribute.len().next_multiple_of(4), 0);
    attribute
}

/// One netlink attribute: a length covering this header and the value, a type, then the value.
fn unpadded(kind: u16, value: &[u8]) -> Vec<u8> {
    let mut attribute = Vec::with_capacity(RTATTR + value.len());
    attribute.extend_from_slice(&((RTATTR + value.len()) as u16).to_ne_bytes());
    attribute.extend_from_slice(&kind.to_ne_bytes());
    attribute.extend_from_slice(value);
    attribute
}

/// An attribute whose header lies about its length: shorter than a header, or past the end of the
/// message carrying it.
fn attribute_of_length(length: u16) -> Vec<u8> {
    let mut attribute = Vec::with_capacity(RTATTR);
    attribute.extend_from_slice(&length.to_ne_bytes());
    attribute.extend_from_slice(&libc::IFA_CACHEINFO.to_ne_bytes());
    attribute
}

/// An address written the way an interface list reports it.
fn addr(text: &str) -> Ipv6Addr {
    text.parse().expect("a valid IPv6 address")
}

/// One of this host's interfaces, as `if-addrs` reports it: only the name and the index carry
/// meaning for the lookup this pins.
fn interface(name: &str, index: u32) -> Interface {
    Interface {
        name: name.to_owned(),
        addr: IfAddr::V6(Ifv6Addr {
            ip: addr("2605:59c1:18c2:df08::5"),
            netmask: addr("ffff:ffff:ffff:ffff::"),
            prefixlen: 64,
            broadcast: None,
        }),
        index: Some(index),
        oper_status: IfOperStatus::Up,
        is_p2p: false,
    }
}
