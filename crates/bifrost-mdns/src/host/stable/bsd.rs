//! Per-address IPv6 flags on macOS and FreeBSD: one `SIOCGIFAFLAG_IN6` ioctl per address, read for
//! `IN6_IFF_TEMPORARY` and `IN6_IFF_DEPRECATED`.
//!
//! The ioctl is a query about an interface, so it needs an AF_INET6 socket only as a handle: this
//! module never sends anything on it. One call per v6 address is the whole cost, and a host has a
//! handful.

use core::ffi::c_char;
use core::net::Ipv6Addr;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

use if_addrs::{IfAddr, Interface};

/// The v6 addresses this host reports as temporary or deprecated.
///
/// Empty when the handle cannot be opened, which keeps every address: see this module's parent for
/// why every failure degrades that way.
pub(super) fn expiring(interfaces: &[Interface]) -> Vec<Ipv6Addr> {
    let socket = match handle() {
        Ok(socket) => socket,
        Err(cause) => {
            tracing::debug!(%cause, "open a handle for per-address IPv6 flags; keeping every address");
            return Vec::new();
        }
    };
    interfaces
        .iter()
        .filter_map(|interface| match interface.addr {
            IfAddr::V6(ref v6) => Some((interface.name.as_str(), v6.ip)),
            IfAddr::V4(_) => None,
        })
        .filter(|(link, ip)| is_expiring(&socket, link, *ip))
        .map(|(_, ip)| ip)
        .collect()
}

/// Whether the kernel reports `ip` on `link` as temporary or deprecated.
///
/// A read that does not succeed answers NO, so the address is kept. The likeliest cause is an
/// address the kernel no longer has, because it went away between the interface enumeration and
/// this call.
fn is_expiring(socket: &OwnedFd, link: &str, ip: Ipv6Addr) -> bool {
    let Some(mut query) = query(link, ip) else {
        return false;
    };
    // SAFETY: the request constant is libc's own for this query, `query` is a live `in6_ifreq`
    // owned by this frame for the whole call, and the kernel reads the name and address written
    // into it and writes back only inside it.
    let answered =
        unsafe { libc::ioctl(socket.as_raw_fd(), libc::SIOCGIFAFLAG_IN6, &raw mut query) };
    if answered < 0 {
        return false;
    }
    // SAFETY: the ioctl returned success, which is the kernel saying it wrote the flags member of
    // the union, so that is the member now holding a value.
    let flags = unsafe { query.ifr_ifru.ifru_flags6 };
    flags & (libc::IN6_IFF_TEMPORARY | libc::IN6_IFF_DEPRECATED) != 0
}

/// The request the ioctl reads: an interface name and the address on it to ask about.
///
/// `None` for a name that does not fit `IFNAMSIZ` with its terminator, which is a name the kernel
/// could not have assigned; asking about a truncated one would be asking about another interface.
fn query(link: &str, ip: Ipv6Addr) -> Option<libc::in6_ifreq> {
    // SAFETY: `in6_ifreq` is a name buffer plus a union of plain-old-data with no niche and no
    // invalid bit pattern, so all-zero is a valid value of it; every field the kernel reads is
    // written below.
    let mut query: libc::in6_ifreq = unsafe { core::mem::zeroed() };
    if link.len() >= query.ifr_name.len() {
        return None;
    }
    for (slot, byte) in query.ifr_name.iter_mut().zip(link.as_bytes()) {
        *slot = *byte as c_char;
    }
    // Writing a union member needs no unsafe; only reading one back does.
    query.ifr_ifru.ifru_addr = libc::sockaddr_in6 {
        sin6_len: size_of::<libc::sockaddr_in6>() as u8,
        sin6_family: libc::AF_INET6 as libc::sa_family_t,
        sin6_port: 0,
        sin6_flowinfo: 0,
        sin6_addr: libc::in6_addr {
            s6_addr: ip.octets(),
        },
        sin6_scope_id: 0,
    };
    Some(query)
}

/// A socket to ask through. Never connected and never written to; the ioctl needs only a
/// descriptor of the right family.
fn handle() -> io::Result<OwnedFd> {
    // SAFETY: `socket` takes three integers and returns an owned descriptor or -1.
    let fd = unsafe { libc::socket(libc::AF_INET6, libc::SOCK_DGRAM, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fd` is a descriptor this call just created, owned by nothing else, handed over
    // exactly once so it is closed exactly once.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}
