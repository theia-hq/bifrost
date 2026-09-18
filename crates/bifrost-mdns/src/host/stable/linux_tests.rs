//! The netlink dump's parse, over fixtures rather than over whatever addresses the running kernel
//! happens to have: the walk is the half of this that can be wrong on any host, so it is the half
//! that is pinned here.

use core::net::Ipv6Addr;

use super::{Flow, NLMSGHDR, RTATTR, scan};

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
    assert_eq!(expiring, vec![temporary]);
}

/// A deprecated address is on its way out at the end of its preferred lifetime, so it is dropped
/// for the same reason a temporary one is: it rots in the hand of the peer it was given to.
#[test]
fn a_deprecated_address_is_reported() {
    let deprecated = addr("2605:59c1:18c2:df08::5");
    let datagram = announcement(deprecated, libc::IFA_F_DEPRECATED, None);

    let mut expiring = Vec::new();
    scan(&datagram, &mut expiring);

    assert_eq!(expiring, vec![deprecated]);
}

/// The header carries eight bits of a field that is thirty-two wide, and a kernel with anything
/// above the byte repeats the whole field in an attribute. The attribute is the one to believe.
#[test]
fn the_full_width_flags_attribute_wins_over_the_truncated_byte() {
    let deprecated = addr("2605:59c1:18c2:df08::5");
    let datagram = announcement(deprecated, 0, Some(libc::IFA_F_DEPRECATED));

    let mut expiring = Vec::new();
    scan(&datagram, &mut expiring);

    assert_eq!(expiring, vec![deprecated]);
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

/// One `RTM_NEWADDR` as the kernel puts it on the socket: an `ifaddrmsg`, the address as an
/// `IFA_ADDRESS` attribute, and the full-width flags as an `IFA_FLAGS` one where `full` says the
/// kernel sends them.
fn announcement(addr: Ipv6Addr, flags: u32, full: Option<u32>) -> Vec<u8> {
    let mut body = vec![
        libc::AF_INET6 as u8,
        64,
        u8::try_from(flags & 0xff).unwrap_or_default(),
        0,
    ];
    // The interface index, which this parse does not read: the dump is per host.
    body.extend_from_slice(&1u32.to_ne_bytes());
    body.extend_from_slice(&attribute(libc::IFA_ADDRESS, &addr.octets()));
    if let Some(full) = full {
        body.extend_from_slice(&attribute(libc::IFA_FLAGS, &full.to_ne_bytes()));
    }
    message(libc::RTM_NEWADDR, &body)
}

/// One netlink message: the header, then the body it announces.
fn message(kind: u16, body: &[u8]) -> Vec<u8> {
    let mut message = Vec::with_capacity(NLMSGHDR + body.len());
    message.extend_from_slice(&((NLMSGHDR + body.len()) as u32).to_ne_bytes());
    message.extend_from_slice(&kind.to_ne_bytes());
    // Flags, sequence and port id, none of which the parse reads.
    message.extend_from_slice(&[0u8; 10]);
    message.extend_from_slice(body);
    message
}

/// One netlink attribute: a length covering this header and the value, a type, then the value.
fn attribute(kind: u16, value: &[u8]) -> Vec<u8> {
    let mut attribute = Vec::with_capacity(RTATTR + value.len());
    attribute.extend_from_slice(&((RTATTR + value.len()) as u16).to_ne_bytes());
    attribute.extend_from_slice(&kind.to_ne_bytes());
    attribute.extend_from_slice(value);
    attribute
}

/// An address written the way an interface list reports it.
fn addr(text: &str) -> Ipv6Addr {
    text.parse().expect("a valid IPv6 address")
}
