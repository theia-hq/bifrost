//! Per-address IPv6 flags on Linux: one netlink `RTM_GETADDR` dump, read for `IFA_F_TEMPORARY` and
//! `IFA_F_DEPRECATED`.
//!
//! The dump answers for the whole host at once, so the interface list is not needed to ask, only
//! to match against afterwards.
//!
//! The unsafe here is confined to three calls that MOVE BYTES: open a socket, send a fixed
//! 24-byte request, receive into a stack buffer. Everything that INTERPRETS those bytes is safe
//! code over `&[u8]`, so the walk that is easy to get wrong is not the walk that could be unsound,
//! and it is exercised from a fixture rather than from whatever the kernel of the day says.

use core::net::Ipv6Addr;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

use if_addrs::Interface;

/// The v6 addresses the kernel reports as temporary or deprecated.
///
/// Empty when the dump cannot be made, which keeps every address: see this module's parent for why
/// every failure degrades that way.
pub(super) fn expiring(_interfaces: &[Interface]) -> Vec<Ipv6Addr> {
    match dump() {
        Ok(expiring) => expiring,
        Err(cause) => {
            tracing::debug!(%cause, "read per-address IPv6 flags over netlink; keeping every address");
            Vec::new()
        }
    }
}

/// One `RTM_GETADDR` dump, gathering what it reports as expiring.
///
/// A dump arrives as a run of datagrams ending in `NLMSG_DONE`. The bound on the run is a guard
/// against a kernel that never sends one, not a real limit: a host with more addresses than this
/// buffer holds has the addresses it did not reach KEPT, which is the safe direction.
fn dump() -> io::Result<Vec<Ipv6Addr>> {
    let socket = netlink()?;
    send(&socket, &request())?;
    let mut expiring = Vec::new();
    let mut datagram = [0u8; 8192];
    for _ in 0..64 {
        let read = receive(&socket, &mut datagram)?;
        if matches!(scan(&datagram[..read], &mut expiring), Flow::Done) {
            break;
        }
    }
    Ok(expiring)
}

/// A `struct nlmsghdr`: a `u32` length, a `u16` type, a `u16` of flags, then a sequence and a port
/// id this crate leaves at zero.
const NLMSGHDR: usize = 16;
/// A `struct ifaddrmsg`: a family, a prefix length, eight bits of flags and a scope, then a `u32`
/// interface index. Attributes follow it.
const IFADDRMSG: usize = 8;
/// A `struct rtattr`: a `u16` length covering this header and its value, then a `u16` type.
const RTATTR: usize = 4;

/// The dump request: every IPv6 address on this host.
///
/// Laid out as bytes rather than through a `#[repr(C)]` struct, because a byte array is already
/// the thing the socket takes and needs no cast to become one.
fn request() -> [u8; NLMSGHDR + IFADDRMSG] {
    let mut request = [0u8; NLMSGHDR + IFADDRMSG];
    request[0..4].copy_from_slice(&((NLMSGHDR + IFADDRMSG) as u32).to_ne_bytes());
    request[4..6].copy_from_slice(&libc::RTM_GETADDR.to_ne_bytes());
    request[6..8].copy_from_slice(&((libc::NLM_F_REQUEST | libc::NLM_F_DUMP) as u16).to_ne_bytes());
    // The sequence number and the port id stay zero: one request per socket, and the kernel fills
    // in the port id of an unbound one itself.
    request[NLMSGHDR] = libc::AF_INET6 as u8;
    request
}

/// Whether the dump has ended, so the caller stops receiving.
enum Flow {
    More,
    Done,
}

/// Read one datagram of the dump, appending every temporary or deprecated address in it.
///
/// Total over arbitrary bytes, and pure: anything that does not parse ENDS the walk, which keeps
/// the addresses it did not reach rather than inventing them.
fn scan(mut datagram: &[u8], expiring: &mut Vec<Ipv6Addr>) -> Flow {
    while let (Some(length), Some(kind)) = (u32_at(datagram, 0), u16_at(datagram, 4)) {
        let length = length as usize;
        if length < NLMSGHDR || length > datagram.len() {
            return Flow::Done;
        }
        if kind == libc::NLMSG_DONE as u16 || kind == libc::NLMSG_ERROR as u16 {
            return Flow::Done;
        }
        if kind == libc::RTM_NEWADDR {
            if let Some(addr) = expiring_addr(&datagram[NLMSGHDR..length]) {
                expiring.push(addr);
            }
        }
        datagram = &datagram[aligned(length).min(datagram.len())..];
    }
    Flow::More
}

/// The address one `RTM_NEWADDR` payload announces, if that address is temporary or deprecated.
fn expiring_addr(payload: &[u8]) -> Option<Ipv6Addr> {
    if *payload.first()? != libc::AF_INET6 as u8 {
        return None;
    }
    // The `ifa_flags` byte in the header is the kernel's truncated copy of a 32-bit field; a
    // kernel new enough to have flags above the byte repeats all of them in an `IFA_FLAGS`
    // attribute, which then wins. Both bits asked about here fit in the byte, so a kernel that
    // sends no attribute is still answered correctly.
    let mut flags = u32::from(*payload.get(2)?);
    let mut addr = None;
    let mut attributes = payload.get(IFADDRMSG..)?;
    while let (Some(length), Some(kind)) = (u16_at(attributes, 0), u16_at(attributes, 2)) {
        let length = length as usize;
        if length < RTATTR || length > attributes.len() {
            break;
        }
        let value = &attributes[RTATTR..length];
        match kind {
            libc::IFA_ADDRESS => {
                addr = <[u8; 16]>::try_from(value).ok().map(Ipv6Addr::from);
            }
            libc::IFA_FLAGS => {
                flags = <[u8; 4]>::try_from(value).map_or(flags, u32::from_ne_bytes);
            }
            _ => {}
        }
        attributes = &attributes[aligned(length).min(attributes.len())..];
    }
    if flags & (libc::IFA_F_TEMPORARY | libc::IFA_F_DEPRECATED) == 0 {
        return None;
    }
    addr
}

/// Where the next netlink item starts: every length is rounded up to four bytes.
fn aligned(length: usize) -> usize {
    length.next_multiple_of(4)
}

/// The `u16` at `offset`, or `None` when the bytes run out first.
fn u16_at(bytes: &[u8], offset: usize) -> Option<u16> {
    let field = bytes.get(offset..offset + 2)?;
    <[u8; 2]>::try_from(field).ok().map(u16::from_ne_bytes)
}

/// The `u32` at `offset`, or `None` when the bytes run out first.
fn u32_at(bytes: &[u8], offset: usize) -> Option<u32> {
    let field = bytes.get(offset..offset + 4)?;
    <[u8; 4]>::try_from(field).ok().map(u32::from_ne_bytes)
}

/// A netlink route socket, with a receive timeout.
///
/// The timeout is the whole reason this is not two lines: the read below runs on the bind path, so
/// a kernel that answers the request and then says nothing more must not park the caller forever.
fn netlink() -> io::Result<OwnedFd> {
    // SAFETY: `socket` takes three integers and returns an owned descriptor or -1.
    let fd = unsafe {
        libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            libc::NETLINK_ROUTE,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fd` is a descriptor this call just created, owned by nothing else, handed over
    // exactly once so it is closed exactly once.
    let socket = unsafe { OwnedFd::from_raw_fd(fd) };
    let timeout = libc::timeval {
        tv_sec: 1,
        tv_usec: 0,
    };
    // SAFETY: the pointer is to a `timeval` live for the call and the length is that type's own
    // size, which is the shape `SO_RCVTIMEO` reads.
    let set = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            core::ptr::from_ref(&timeout).cast(),
            size_of::<libc::timeval>() as libc::socklen_t,
        )
    };
    if set < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(socket)
}

/// Send the dump request. The socket is unbound and unconnected, which for netlink means the
/// kernel.
fn send(socket: &OwnedFd, request: &[u8]) -> io::Result<()> {
    // SAFETY: the pointer and the length describe `request`, which outlives the call.
    let sent = unsafe {
        libc::send(
            socket.as_raw_fd(),
            request.as_ptr().cast(),
            request.len(),
            0,
        )
    };
    if sent < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Receive one datagram of the answer, returning how much of `datagram` it filled.
fn receive(socket: &OwnedFd, datagram: &mut [u8]) -> io::Result<usize> {
    // SAFETY: the pointer and the length describe `datagram`, which is borrowed mutably for the
    // call, so nothing else reads it while the kernel writes.
    let read = unsafe {
        libc::recv(
            socket.as_raw_fd(),
            datagram.as_mut_ptr().cast(),
            datagram.len(),
            0,
        )
    };
    // The only value that does not convert is a negative one, which is the error return: the
    // length handed in is a slice's, so the success return always fits.
    usize::try_from(read).map_err(|_| io::Error::last_os_error())
}

#[cfg(test)]
#[path = "linux_tests.rs"]
mod linux_tests;
