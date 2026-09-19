//! The request the ioctl reads, which is the one half of this path a fixture can reach: the call
//! itself needs a live kernel, the buffer handed to it does not. The interesting case is the name
//! that does not fit, because a truncated name is a valid name for a DIFFERENT interface, so the
//! wrong answer here is a confident answer about the wrong link.

use core::net::Ipv6Addr;

use super::query;

/// `IFNAMSIZ` is 16 bytes INCLUDING the terminator, so 15 is the longest name a query may carry
/// and the zeroed tail is what terminates it.
#[test]
fn a_name_that_fits_is_written_with_its_terminator() {
    for length in [14, 15] {
        let link = "e".repeat(length);

        let query = query(&link, addr()).expect("a name shorter than IFNAMSIZ");

        assert_eq!(query.ifr_name.len(), 16, "IFNAMSIZ, terminator included");
        assert_eq!(
            query.ifr_name[length], 0,
            "the byte past the name is the terminator the kernel reads to"
        );
        let written: Vec<u8> = query.ifr_name[..length]
            .iter()
            .map(|slot| *slot as u8)
            .collect();
        assert_eq!(
            written,
            link.as_bytes(),
            "the name round-trips byte for byte"
        );
    }
}

/// A name with no room for a terminator is REFUSED, never truncated: the kernel could not have
/// assigned it, and asking about the first fifteen bytes of it asks about another interface.
#[test]
fn a_name_that_cannot_fit_is_refused_rather_than_truncated() {
    for length in [16, 17] {
        assert!(
            query(&"e".repeat(length), addr()).is_none(),
            "a name of {length} bytes does not fit IFNAMSIZ with its terminator"
        );
    }
}

/// The other half of the request: the address being asked about, in the shape this ioctl reads it.
#[test]
fn the_query_carries_the_address_it_asks_about() {
    let ip = addr();

    let query = query("en0", ip).expect("a name that fits");

    // SAFETY: the address is the union member this frame just wrote, and nothing has touched the
    // value since, so that is the member holding a value.
    let asked = unsafe { query.ifr_ifru.ifru_addr };
    assert_eq!(asked.sin6_addr.s6_addr, ip.octets());
    assert_eq!(asked.sin6_family, libc::AF_INET6 as libc::sa_family_t);
    assert_eq!(
        asked.sin6_len,
        size_of::<libc::sockaddr_in6>() as u8,
        "the kernel reads a sockaddr's own length out of it"
    );
}

/// An address of the shape this read is for: a global IPv6 one.
fn addr() -> Ipv6Addr {
    "2605:59c1:18c2:df08:7c65:e101:392a:62b1"
        .parse()
        .expect("a valid IPv6 address")
}
