//! Which of this host's addresses it will still be answering on tomorrow.
//!
//! An IPv6 interface routinely carries two global addresses at once: the STABLE one derived from
//! the prefix, and an RFC 8981 TEMPORARY (privacy) address that is deprecated within a day and
//! withdrawn within a week. The two are indistinguishable by their bits, so nothing downstream can
//! tell them apart, and handing a peer the temporary one hands them an address that rots. It is
//! also, by construction, the one address on the interface that privacy addressing exists to keep
//! unpublished, so putting it on a screen defeats the feature it came from.
//!
//! `if-addrs` reports an INTERFACE's flags and never an ADDRESS's, so the flags come from the
//! platform: a netlink `RTM_GETADDR` dump on Linux, the `SIOCGIFAFLAG_IN6` ioctl on macOS and
//! FreeBSD, and nothing at all anywhere else.
//!
//! EVERY path degrades by KEEPING the address. An address dropped because a syscall failed is a
//! peer that cannot dial this host at all; an address kept because its flags could not be read is,
//! at worst, the address this host has always handed out. So the rule is one-directional: drop
//! only what the kernel POSITIVELY reports as temporary or deprecated.
//!
//! Selecting for durability selects FOR the durable identifier, which is worth saying out loud.
//! A LAN observer used to hear both of an interface's global addresses and now hears exactly one,
//! and by construction that one is the address that persists. Under RFC 7217 stable-privacy
//! addressing (macOS, and Linux with `addr_gen_mode=3`) it is per-prefix and carries nothing
//! between networks; on a Linux host still generating EUI-64 addresses it is the MAC-derived one,
//! which this mechanism then guarantees is the address published. Nothing NEW leaks (the pair was
//! already on the wire), but the durable half is now the only thing on offer, and that is the
//! feature rather than an accident of it.

use core::net::{IpAddr, Ipv6Addr};

use if_addrs::Interface;

/// Sift this host's interfaces into the ones it will still be answering on tomorrow, and what the
/// per-address flag read said about the rest.
pub(super) fn sift(interfaces: Vec<Interface>) -> (Vec<Interface>, Lifetimes) {
    let reported = match expiring(&interfaces) {
        Ok(reported) => reported,
        // Logged once here rather than in each port, so a new port is a function that reads flags
        // and nothing else. The errno is the whole story of the failure and belongs in the log;
        // what travels to a surface is only that the flags went unread.
        Err(cause) => {
            tracing::debug!(%cause, "read per-address IPv6 flags; keeping every address");
            return (interfaces, Lifetimes::Unread);
        }
    };
    let (stable, dropped) = split(interfaces, &reported);
    (stable, Lifetimes::Expiring(dropped))
}

/// What this host said about how long its addresses last.
pub(super) enum Lifetimes {
    /// The interfaces whose address this host reports as temporary or deprecated, which is empty
    /// when it reports none of them.
    Expiring(Vec<Interface>),
    /// Nothing at all: the flags could not be read, so no address here can be told from any other
    /// and every one of them is kept. Distinct from reporting none, because a set that could not
    /// be checked may still be carrying an address that rots.
    Unread,
}

/// Split `interfaces` into the ones `reported` does not name and the ones it does.
///
/// Matched on the LINK as well as the address, which is why each port returns both: the same
/// address can sit on two links, and only the one the kernel flagged is on its way out. A v4
/// address is never matched at all, because only IPv6 has the temporary-address mechanism this
/// reads for.
fn split(
    interfaces: Vec<Interface>,
    reported: &[(String, Ipv6Addr)],
) -> (Vec<Interface>, Vec<Interface>) {
    interfaces
        .into_iter()
        .partition(|interface| match interface.ip() {
            IpAddr::V6(v6) => !reported
                .iter()
                .any(|(link, ip)| *ip == v6 && *link == interface.name),
            IpAddr::V4(_) => true,
        })
}

// The platform's own answer, always under the one name `expiring`, so the policy above is written
// once and each port is a leaf: it reads flags and names addresses, and knows nothing of what the
// caller does with them.
#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
use linux::expiring;

#[cfg(any(target_vendor = "apple", target_os = "freebsd"))]
mod bsd;
#[cfg(any(target_vendor = "apple", target_os = "freebsd"))]
use bsd::expiring;

/// Every other target, Windows first among them: keep every address, knowingly.
///
/// Not a platform limit. Windows reports the same facts through `GetAdaptersAddresses`
/// (`SuffixOrigin`, and a preferred lifetime of zero), and the remaining BSDs have the ioctl under
/// their own headers. It is that each one is a separate OS binding this project has no way to
/// exercise, and an unexercised binding that DROPS addresses is the failure mode worth avoiding:
/// the cost of keeping a temporary address is one line that rots, the cost of a wrong drop is a
/// host nobody can reach. Implementing this function is all a port takes.
///
/// A clean read of nothing, not a failed one: a port that does not exist is not a read that
/// failed, and a caveat on every line this OS ever prints is noise no operator can act on.
#[cfg(not(any(target_os = "linux", target_vendor = "apple", target_os = "freebsd")))]
fn expiring(_interfaces: &[Interface]) -> std::io::Result<Vec<(String, Ipv6Addr)>> {
    Ok(Vec::new())
}

#[cfg(test)]
#[path = "stable_tests.rs"]
mod stable_tests;
