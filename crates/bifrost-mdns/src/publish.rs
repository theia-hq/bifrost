//! What this node puts on the wire: which of the sockets a bind answers on may be published,
//! choosing the port, and naming what the resulting advertisement actually reaches.
//!
//! The addresses come from [`Dialable`](crate::Dialable), which expands bind truth
//! (`bifrost::Transport::bound_sockets`) through this host's interfaces. Publication is POLICY over
//! that fact, and it lives here rather than in the expansion because the rule is this consumer's
//! own: a peer only ever hears this node's multicast query over a link with a network behind it, so
//! only an address on such a link may go in a record, while a loopback address may go in one exactly
//! when the operator bound loopback themselves.

use core::net::{IpAddr, Ipv4Addr, SocketAddr};

use crate::MdnsError;
use crate::host::{Dialable, Missing, Scope};

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
    ///
    /// The eligible set is this crate's OWN rule over the sockets the bind answers on: an address on
    /// a link with a network behind it, which is the only kind a peer that hears this node's
    /// multicast query can arrive over, plus any socket the operator named in the bind VERBATIM,
    /// which is what makes a deliberate `127.0.0.1` bind publishable while a wildcard's loopback is
    /// not. Everything else the bind answers on (a tunnel address, a wildcard's loopback) is
    /// handable by a person and unpublishable here.
    pub(crate) fn of(bound: Vec<SocketAddr>) -> Self {
        // The bind set outlives the expansion because the containment test below is what tells a
        // deliberate loopback bind from a wildcard that merely answers there.
        Self::of_dialable(Dialable::of(bound.clone()), &bound)
    }

    /// Decide what the sockets a bind answers on put on the wire, given the bind they came from.
    pub(crate) fn of_dialable(dialable: Dialable, bound: &[SocketAddr]) -> Self {
        let (dialable, missing) = dialable.into_parts();
        // The interface list is only ever needed to expand a wildcard, so failing to read it leaves
        // nothing to publish rather than nothing to run: browsing does not depend on it. It is also
        // the only thing whose absence changes this decision: unread per-address flags leave every
        // address in hand, and an address dropped as expiring is one this node must not publish
        // anyway, so both leave a record this crate can still stand behind.
        if let Missing::Interfaces(cause) = missing {
            return Self::BrowseOnly(MdnsError::Interfaces(cause));
        }
        Self::of_publishable(
            dialable
                .into_iter()
                // BOTH routable classes publish. The split between them is a distinction the
                // BANNER draws for an operator choosing an address by hand; a record is read by a
                // machine that will try what it is given, and an address reaching only this network
                // is exactly what a record broadcast on this network is for. Folding the split in
                // here would have dropped every internet address off the wire.
                .filter(|at| {
                    matches!(at.scope, Scope::Internet | Scope::Network)
                        || bound.contains(&at.socket)
                })
                .map(|at| at.socket)
                .collect::<Vec<_>>(),
        )
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
