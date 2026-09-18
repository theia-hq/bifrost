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

use core::net::{IpAddr, Ipv6Addr};

use if_addrs::Interface;

/// Keep only the addresses this host is not about to stop answering on.
pub(super) fn only(mut interfaces: Vec<Interface>) -> Vec<Interface> {
    let dropped: Vec<Ipv6Addr> = expiring(&interfaces);
    interfaces.retain(|interface| match interface.ip() {
        IpAddr::V6(v6) => !dropped.contains(&v6),
        IpAddr::V4(_) => true,
    });
    interfaces
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
#[cfg(not(any(target_os = "linux", target_vendor = "apple", target_os = "freebsd")))]
fn expiring(_interfaces: &[Interface]) -> Vec<Ipv6Addr> {
    Vec::new()
}
