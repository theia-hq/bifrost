//! What this node puts on the wire: expanding a bind set into publishable addresses, choosing the
//! port, and naming what the resulting advertisement actually reaches.
//!
//! The input is bind truth (`bifrost::Transport::bound_sockets`): the sockets as bound, with an
//! unspecified IP preserved. Publication is policy over that fact, and it lives here rather than in
//! a transport because only a publisher knows that `0.0.0.0` has to become this host's real
//! addresses while `127.0.0.1` has to stay exactly itself.

use core::net::{IpAddr, Ipv4Addr, SocketAddr};

use if_addrs::Interface;

use crate::MdnsError;

/// What an mDNS advertisement reaches, as a surface reads it before it claims anything.
///
/// The discovery value alone cannot tell these apart: a browse-only instance browses exactly like an
/// advertising one, and a loopback-only record is invisible to every other host while looking, from
/// the inside, like a live advertisement. Naming each state, with the cause for every degraded one,
/// is what lets a surface say what is true instead of promising a reach this node does not have.
#[derive(Debug)]
pub enum Advertising {
    /// Publishing at least one non-loopback address: a peer on another host can hear this node and
    /// dial what it heard.
    OnLan(Advertised),
    /// Publishing only loopback addresses: another process on this machine can find this node, and
    /// no other host can, because a loopback address names the dialer's own machine.
    LoopbackOnly(Advertised),
    /// Publishing nothing, browsing all the same: this node hears peers and puts no record of its
    /// own on the wire. Not the same as discovery being off, which hears nothing either.
    BrowseOnly(MdnsError),
}

impl Advertising {
    /// Decide what `bound` puts on the wire, reading this host's interfaces if a wildcard needs
    /// expanding.
    pub(crate) fn of(bound: Vec<SocketAddr>) -> Self {
        match HostAddrs::publishable(bound) {
            Ok(publishable) => Self::of_publishable(publishable),
            // The interface list is only ever needed to expand a wildcard, so failing to read it
            // leaves nothing to publish rather than nothing to run: browsing does not depend on it.
            Err(cause) => Self::BrowseOnly(cause),
        }
    }

    /// Decide what an already-expanded address set puts on the wire.
    ///
    /// Every address here is concrete, so the only questions left are which port the record names
    /// ([`Advertised::of`]) and how far the result reaches. Nothing publishable is a state, never a
    /// failure: the browse half works regardless, and a node that only listens is the honest
    /// outcome for a bind with no address a peer could dial.
    pub(crate) fn of_publishable(publishable: Vec<SocketAddr>) -> Self {
        match Advertised::of(publishable) {
            Ok(advertised) if advertised.reaches_off_host() => Self::OnLan(advertised),
            Ok(advertised) => Self::LoopbackOnly(advertised),
            Err(cause) => Self::BrowseOnly(cause),
        }
    }

    /// The record this node publishes, or `None` when it publishes none.
    pub fn advertised(&self) -> Option<&Advertised> {
        match self {
            Self::OnLan(advertised) | Self::LoopbackOnly(advertised) => Some(advertised),
            Self::BrowseOnly(_) => None,
        }
    }
}

/// The addresses one mDNS advertisement carries: a port plus the bound addresses on it, at least one.
///
/// Non-empty and single-port by construction, so a holder never has to ask whether there is anything
/// to publish: only this crate builds one, from a bind set it has already checked.
#[derive(Debug)]
pub struct Advertised {
    /// The port every advertised address is bound on.
    port: u16,
    /// The bound addresses on that port, at least one.
    addrs: Vec<SocketAddr>,
}

impl Advertised {
    /// Choose what to advertise from a bind's publishable addresses.
    ///
    /// A single-port bind (the common shape: one listener across interfaces) advertises every address
    /// exactly as given, whatever family. A multi-port bind (iroh binds a v4 and a v6 socket on
    /// different ephemeral ports) advertises the port of the first IPv4 socket in bind order: the
    /// family mDNS queries egress on here, and the address a peer dials. Addresses on other ports are
    /// left out rather than folded into a port that cannot carry them. Advertising one port is this
    /// crate's policy, not a limit of the protocol (a record can name several address-port pairs); it
    /// keeps every advertised address dialable on the same port, so a peer never has to guess. A
    /// multi-port bind with no IPv4 socket has nothing a peer on that query path could dial, so it is
    /// a named error, never a partial or guessed advertisement.
    pub(crate) fn of(addrs: impl IntoIterator<Item = SocketAddr>) -> Result<Self, MdnsError> {
        let addrs: Vec<SocketAddr> = addrs.into_iter().collect();
        let Some(first) = addrs.first() else {
            return Err(MdnsError::NoAddrs);
        };
        if addrs.iter().all(|addr| addr.port() == first.port()) {
            return Ok(Self {
                port: first.port(),
                addrs,
            });
        }
        let port = addrs
            .iter()
            .find(|addr| addr.is_ipv4())
            .map(SocketAddr::port)
            .ok_or(MdnsError::NoV4Addrs)?;
        let addrs = addrs
            .into_iter()
            .filter(|addr| addr.port() == port)
            .collect();
        Ok(Self { port, addrs })
    }

    /// The port this record names. Every address in [`Self::addrs`] is on it.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// The addresses this record carries, at least one.
    pub fn addrs(&self) -> &[SocketAddr] {
        &self.addrs
    }

    /// The interfaces this node's multicast queries egress on: the IPv4 half of the very set it
    /// publishes.
    ///
    /// One set feeds both, so a peer can never be handed an address this node does not send queries
    /// from. Without the pin the kernel picks an egress interface off the routing table, which can
    /// miss a multi-homed peer; the dependency's own v4 leg is the only one that reaches here, so
    /// only the IPv4 addresses can serve as pins.
    pub(crate) fn egress_v4(&self) -> Vec<Ipv4Addr> {
        self.addrs
            .iter()
            .filter_map(|addr| match addr.ip() {
                IpAddr::V4(v4) => Some(v4),
                IpAddr::V6(_) => None,
            })
            .collect()
    }

    /// Whether this record reaches past the machine it was published from.
    fn reaches_off_host(&self) -> bool {
        self.addrs.iter().any(|addr| !addr.ip().is_loopback())
    }
}

/// The concrete addresses this host's interfaces carry, the source a wildcard bind expands into.
///
/// A seam, not an implementation detail: the expansion is policy over a list the OS hands back, and a
/// test that had to take the machine's real interfaces could assert nothing about it. Reading the
/// live list is [`HostAddrs::of_this_host`]; everything downstream of it works over any list.
#[derive(Debug)]
pub(crate) struct HostAddrs(pub(crate) Vec<IpAddr>);

impl HostAddrs {
    /// The addresses `bound` can publish: every concrete address exactly as bound, every unspecified
    /// one expanded through this host's interfaces.
    ///
    /// The interface list is read only when a wildcard is actually present, so a bind that named its
    /// own addresses never pays the syscall and never fails on it.
    fn publishable(bound: Vec<SocketAddr>) -> Result<Vec<SocketAddr>, MdnsError> {
        if !bound.iter().any(|socket| socket.ip().is_unspecified()) {
            return Ok(bound);
        }
        Ok(Self::of_this_host()?.expand(bound))
    }

    /// Read this host's live interfaces.
    fn of_this_host() -> Result<Self, MdnsError> {
        let interfaces = if_addrs::get_if_addrs().map_err(MdnsError::Interfaces)?;
        Ok(Self::of_interfaces(interfaces))
    }

    /// The addresses of the interfaces a wildcard bind may be advertised at.
    ///
    /// Three kinds of interface are left out, because an address taken from one is an address a peer
    /// cannot use. An interface the OS does not report as running is not one this node can be
    /// reached at, and publishing its address costs a dialing peer a timeout. A point-to-point link
    /// (utun, tun, wg, a tailnet) has no LAN behind it: nothing that hears this node's multicast
    /// query arrives over it, its address sorts below the real LAN address on the dialer, and a
    /// transport that dials only the first hint it is handed would spend the dial there. A
    /// link-local address means nothing without the scope of the interface it came from, which no
    /// record carries. This is the mechanism deciding what it can honestly publish, not an operator
    /// policy over which of several reachable addresses to prefer.
    pub(crate) fn of_interfaces(interfaces: Vec<Interface>) -> Self {
        Self(
            interfaces
                .into_iter()
                .filter(|interface| {
                    interface.is_oper_up() && !interface.is_p2p() && !interface.is_link_local()
                })
                .map(|interface| interface.ip())
                .collect(),
        )
    }

    /// Expand a bind set into the addresses to publish.
    ///
    /// Only an unspecified address expands: `0.0.0.0` means "every IPv4 interface", so it stands for
    /// this host's concrete IPv4 addresses on that port, minus loopback, which no peer off this host
    /// can dial and which a wildcard must therefore never put on the wire. A concrete address is
    /// published exactly as bound, loopback included and never expanded: a caller that bound
    /// `127.0.0.1` asked for a host-local service, and expanding that into LAN addresses would
    /// publish a reach it deliberately did not bind.
    pub(crate) fn expand(&self, bound: Vec<SocketAddr>) -> Vec<SocketAddr> {
        let mut publishable: Vec<SocketAddr> = Vec::with_capacity(bound.len());
        for socket in bound {
            if !socket.ip().is_unspecified() {
                push_once(&mut publishable, socket);
                continue;
            }
            for host in self.same_family_off_host(socket.ip()) {
                push_once(&mut publishable, SocketAddr::new(host, socket.port()));
            }
        }
        publishable
    }

    /// This host's dialable addresses in the same family as `wildcard`. A v4 wildcard stands for v4
    /// interfaces and a v6 wildcard for v6 ones; publishing across families would name an address on
    /// a socket that never bound it.
    ///
    /// Loopback and link-local are dropped here as well as at the interface, so a list assembled any
    /// other way still cannot put a `fe80::` in a record: the scope that address needs to mean
    /// anything is not something mDNS carries.
    fn same_family_off_host(&self, wildcard: IpAddr) -> impl Iterator<Item = IpAddr> {
        self.0.iter().copied().filter(move |host| {
            host.is_ipv4() == wildcard.is_ipv4() && !host.is_loopback() && !is_link_local(*host)
        })
    }
}

/// Whether `addr` is link-local: `169.254.0.0/16`, or `fe80::/10` matched by its prefix because
/// `Ipv6Addr` has no stable accessor for it.
fn is_link_local(addr: IpAddr) -> bool {
    match addr {
        IpAddr::V4(v4) => v4.is_link_local(),
        IpAddr::V6(v6) => v6.segments()[0] & 0xffc0 == 0xfe80,
    }
}

/// Append `socket` unless it is already present. Two wildcards on one port expand into the same host
/// addresses, and a duplicate would be published and pinned twice for no gain.
fn push_once(publishable: &mut Vec<SocketAddr>, socket: SocketAddr) {
    if !publishable.contains(&socket) {
        publishable.push(socket);
    }
}
