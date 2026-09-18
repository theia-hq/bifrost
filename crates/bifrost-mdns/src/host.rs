//! Turning bind truth into the concrete sockets a bind answers on, each carrying how far it reaches.
//!
//! The input is bind truth (`bifrost::Transport::bound_sockets`): the sockets as bound, with an
//! unspecified IP preserved. A concrete socket answers at itself; a wildcard answers at every
//! interface address of its family, and at loopback. That expansion is the only code in the family
//! that turns a bind into addresses, and it has two consumers with genuinely different rules: this
//! crate's advertiser, which may publish only what a peer hearing a multicast query could dial, and a
//! surface that hands an operator addresses to pass to a peer by hand. So the reach of each address
//! is a FACT the entry carries, and each consumer applies its own rule to it, rather than one
//! consumer reading the other's filtered result.

use core::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use if_addrs::Interface;

use crate::MdnsError;

/// How far an address this bind answers on can be routed from.
///
/// Not a ranking of quality: which entry is right depends on where the peer is, and nothing on this
/// host knows that. It is who can route to the address, which is what a consumer needs to decide
/// whether it may publish the address, and what a surface needs to mark it with.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Reach {
    /// A globally routable address: a peer anywhere on the internet can route to it, given a path.
    /// The only class that reaches a peer who is not already on a network or an overlay with this
    /// host, which on a transport with no relay and no NAT traversal is the only way to reach one
    /// at all.
    Internet,
    /// A link with a network behind it, and that network is where it stops: a private or
    /// unique-local address reaches a peer on this network and no further. Distinct from
    /// [`Internet`](Self::Internet) because the two look alike and do not behave alike, and a line
    /// that did not say which claimed the wider reach for both.
    Network,
    /// A point-to-point link (utun, tun, wg, a tailnet), named because the link is what says who can
    /// route to it: a peer on that same overlay, and nobody else.
    Tunnel {
        /// The interface the address sits on, as the OS names it (`utun4`). The truth this host
        /// has: what the link joins is the operator's knowledge, never this crate's to claim.
        link: String,
    },
    /// Loopback: this address names the DIALER's own machine, so it reaches another process here
    /// and no other host.
    ThisMachine,
}

impl Reach {
    /// The sort key behind [`Dialable::all`]'s order, by how far an address reaches without the peer
    /// first joining something: anyone who can route to it, anyone on that one named link, this
    /// machine. Private and numeric only to sort: an `Ord` on the enum would order two tunnels by
    /// link name and lose the interface order the OS reported them in.
    fn rank(&self) -> u8 {
        match self {
            Self::Internet => 0,
            Self::Network => 1,
            Self::Tunnel { .. } => 2,
            Self::ThisMachine => 3,
        }
    }
}

/// One socket this bind answers on, and how far that socket reaches.
#[derive(Debug, PartialEq, Eq)]
pub struct At {
    /// The concrete socket: never an unspecified IP, always the bound port.
    pub socket: SocketAddr,
    /// Who can route to [`socket`](Self::socket).
    pub reach: Reach,
}

/// The sockets a bind answers on, expanded from bind truth through this host's interfaces.
///
/// Built by [`of`](Self::of), which is TOTAL: an interface list the OS will not hand over yields
/// what is derivable without one (every concrete socket, and each wildcard's loopback) and carries
/// the cause, so a consumer renders a short list instead of growing an error branch for a syscall.
#[derive(Debug)]
pub struct Dialable {
    /// The entries, in [`all`](Self::all)'s order.
    addrs: Vec<At>,
    /// Why the expanded half may be short: the interface read failed. `None` when the read
    /// succeeded, and when no wildcard made it necessary.
    interfaces: Option<MdnsError>,
}

impl Dialable {
    /// Expand `bound` into the sockets it answers on.
    ///
    /// The interface list is read only when a wildcard is actually present, so a bind that named its
    /// own addresses never pays the syscall and never carries a cause.
    pub fn of(bound: Vec<SocketAddr>) -> Self {
        if !bound.iter().any(|socket| socket.ip().is_unspecified()) {
            return Self {
                addrs: HostAddrs(Vec::new()).expand(bound),
                interfaces: None,
            };
        }
        Self::of_host(HostAddrs::of_this_host(), bound)
    }

    /// Expand `bound` against the result of reading this host's interfaces.
    ///
    /// The seam [`of`](Self::of) is written over, so the failed-read half is exercised by a test
    /// that hands it the failure, and every other case by a test that hands it a fixed host.
    pub(crate) fn of_host(host: Result<HostAddrs, MdnsError>, bound: Vec<SocketAddr>) -> Self {
        match host {
            Ok(host) => Self {
                addrs: host.expand(bound),
                interfaces: None,
            },
            // Total by construction: an empty interface list still expands a wildcard into the
            // loopback socket it genuinely answers on, and the cause rides along for the consumer
            // whose own outcome depends on it.
            Err(cause) => Self {
                addrs: HostAddrs(Vec::new()).expand(bound),
                interfaces: Some(cause),
            },
        }
    }

    /// Every socket this bind answers on: [`Network`] first, then [`Tunnel`], then [`ThisMachine`],
    /// each group in the order the host reported its interfaces.
    ///
    /// [`Network`]: Reach::Network
    /// [`Tunnel`]: Reach::Tunnel
    /// [`ThisMachine`]: Reach::ThisMachine
    pub fn all(&self) -> &[At] {
        &self.addrs
    }

    /// Why the expanded half may be short, or `None` when nothing was missed.
    pub fn interfaces(&self) -> Option<&MdnsError> {
        self.interfaces.as_ref()
    }

    /// Split into the entries and the interface-read cause, for the one consumer that reports that
    /// cause as its OWN outcome and so has to own it rather than borrow it.
    pub(crate) fn into_parts(self) -> (Vec<At>, Option<MdnsError>) {
        (self.addrs, self.interfaces)
    }
}

impl FromIterator<At> for Dialable {
    /// Assemble a set from entries already in hand, ordering them exactly as an expansion would.
    ///
    /// The order is [`all`](Dialable::all)'s invariant, so it is established here too rather than
    /// trusted from the caller: a value built this way is indistinguishable from an expanded one,
    /// which is what lets a consumer drive its own rendering over a host it does not have (a tunnel
    /// link, a second network address). Nothing was read, so nothing is short:
    /// [`interfaces`](Dialable::interfaces) is `None`.
    fn from_iter<I: IntoIterator<Item = At>>(entries: I) -> Self {
        let mut addrs: Vec<At> = entries.into_iter().collect();
        addrs.sort_by_key(|at| at.reach.rank());
        Self {
            addrs,
            interfaces: None,
        }
    }
}

/// The concrete addresses this host's interfaces carry, the source a wildcard bind expands into.
///
/// A seam, not an implementation detail: the expansion is policy over a list the OS hands back, and a
/// test that had to take the machine's real interfaces could assert nothing about it. Reading the
/// live list is [`HostAddrs::of_this_host`]; everything downstream of it works over any list.
#[derive(Debug)]
pub(crate) struct HostAddrs(pub(crate) Vec<HostAddr>);

/// One of this host's interface addresses, before a bound port makes it a socket.
#[derive(Debug)]
pub(crate) struct HostAddr {
    /// The interface's address.
    pub(crate) ip: IpAddr,
    /// Who can route to it, read off the link it sits on.
    pub(crate) reach: Reach,
}

impl HostAddrs {
    /// Read this host's live interfaces.
    fn of_this_host() -> Result<Self, MdnsError> {
        let interfaces = if_addrs::get_if_addrs().map_err(MdnsError::Interfaces)?;
        Ok(Self::of_interfaces(interfaces))
    }

    /// The addresses of the interfaces a wildcard bind answers on, each with its reach.
    ///
    /// Two kinds of interface are left out, because an address taken from one is an address NEITHER
    /// consumer can use. An interface the OS does not report as running is not one this node answers
    /// on, and naming it costs a dialing peer a timeout. A link-local address means nothing without
    /// the scope of the interface it came from, which neither a record nor a pasted address carries.
    /// A point-to-point link (utun, tun, wg, a tailnet) is NOT dropped: the socket observably answers
    /// there, so the fact that the link has no network behind it is carried as [`Reach::Tunnel`] and
    /// left to each consumer, which is what stops one consumer's publication policy from deciding
    /// what the other may hand a human.
    pub(crate) fn of_interfaces(interfaces: Vec<Interface>) -> Self {
        Self(
            interfaces
                .into_iter()
                .filter(|interface| interface.is_oper_up() && !interface.is_link_local())
                .map(|interface| HostAddr {
                    ip: interface.ip(),
                    // Loopback first: a loopback interface is not a point-to-point link, and calling
                    // it a network one would say a peer elsewhere could route to it.
                    // Loopback first, then the link shape, and only then the address itself. The
                    // order matters: a tunnel address is routinely inside a range that reads as
                    // one thing by prefix and behaves as another, and the link is the better
                    // evidence when we have it.
                    reach: if interface.ip().is_loopback() {
                        Reach::ThisMachine
                    } else if interface.is_p2p() {
                        Reach::Tunnel {
                            link: interface.name,
                        }
                    } else if is_globally_routable(interface.ip()) {
                        Reach::Internet
                    } else {
                        Reach::Network
                    },
                })
                .collect(),
        )
    }

    /// Expand a bind set into the sockets it answers on, in [`Dialable::all`]'s order.
    ///
    /// A concrete address answers at exactly itself and is never expanded: a caller that bound
    /// `127.0.0.1` asked for a host-local service, and expanding that into this host's other
    /// addresses would claim a reach it deliberately did not bind. An unspecified address means
    /// "every interface of this family", so it stands for this host's concrete addresses in that
    /// family, plus loopback, which the wildcard genuinely answers on too.
    pub(crate) fn expand(&self, bound: Vec<SocketAddr>) -> Vec<At> {
        let mut dialable: Vec<At> = Vec::with_capacity(bound.len());
        for socket in bound {
            if !socket.ip().is_unspecified() {
                // Without a wildcard there is no interface list to match a concrete address against,
                // so its reach is what the address itself says. A concrete tunnel bind therefore
                // reads as `Network`: the one caller that binds concretely names a LAN address, and
                // inventing a syscall to sharpen a case nobody has would buy nothing.
                let reach = if socket.ip().is_loopback() {
                    Reach::ThisMachine
                } else if is_globally_routable(socket.ip()) {
                    Reach::Internet
                } else {
                    Reach::Network
                };
                push_once(&mut dialable, socket, reach);
                continue;
            }
            for host in self.same_family(socket.ip()) {
                push_once(
                    &mut dialable,
                    SocketAddr::new(host.ip, socket.port()),
                    host.reach.clone(),
                );
            }
            // The wildcard's own loopback socket, whether or not the interface list named one (it
            // does not when the read failed): a wildcard bind answers there, and for an isolated
            // host it is the only address it answers on at all.
            push_once(
                &mut dialable,
                SocketAddr::new(loopback_of(socket.ip()), socket.port()),
                Reach::ThisMachine,
            );
        }
        // Stable, so the interface order the OS reported survives inside each group.
        dialable.sort_by_key(|at| at.reach.rank());
        dialable
    }

    /// This host's addresses in the same family as `wildcard`. A v4 wildcard stands for v4 interfaces
    /// and a v6 wildcard for v6 ones; crossing families would name an address on a socket that never
    /// bound it.
    ///
    /// Link-local is dropped here as well as at the interface, so a list assembled any other way
    /// still cannot yield a `fe80::`: the scope that address needs to mean anything is carried
    /// neither on the mDNS wire nor in an address a person pastes.
    fn same_family(&self, wildcard: IpAddr) -> impl Iterator<Item = &HostAddr> {
        self.0
            .iter()
            .filter(move |host| host.ip.is_ipv4() == wildcard.is_ipv4() && !is_link_local(host.ip))
    }
}

/// The loopback address of `family`'s own family, the address every wildcard bind also answers on.
fn loopback_of(family: IpAddr) -> IpAddr {
    match family {
        IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::LOCALHOST),
    }
}

/// Whether `addr` is link-local: `169.254.0.0/16`, or `fe80::/10` matched by its prefix because
/// `Ipv6Addr` has no stable accessor for it.
/// Whether `addr` is one a peer anywhere on the internet could route to, given a path.
///
/// Spelled out rather than taken from the standard library: the `is_global` family is still
/// unstable, and the shape this needs is narrow enough that naming the ranges is clearer than
/// waiting for it. Asked only AFTER the loopback and point-to-point tests, so a tunnel address
/// whose range happens to read one way is already classified by its link, which is better evidence.
///
/// v4: everything that is not reserved for somewhere smaller than the internet. v6: the single
/// global-unicast prefix `2000::/3`, which is what a routable v6 address is by definition and which
/// excludes unique-local `fc00::/7` and link-local `fe80::/10` without naming them.
fn is_globally_routable(addr: IpAddr) -> bool {
    match addr {
        IpAddr::V4(v4) => {
            !v4.is_private()
                && !v4.is_loopback()
                && !v4.is_link_local()
                && !v4.is_broadcast()
                && !v4.is_multicast()
                && !v4.is_unspecified()
                && !v4.is_documentation()
                // Carrier-grade NAT, `100.64.0.0/10`: a provider's own space, and the range a
                // tailnet hands out, so an overlay address that escaped the link test still does
                // not read as internet-routable.
                && !(v4.octets()[0] == 100 && (64..128).contains(&v4.octets()[1]))
        }
        // The global-unicast prefix, minus the documentation range `2001:db8::/32`, which sits
        // inside it and is reserved rather than routable. The v4 arm excludes its documentation
        // ranges through `is_documentation`; v6 has no stable equivalent, so it is named here.
        IpAddr::V6(v6) => {
            v6.segments()[0] & 0xe000 == 0x2000
                && !(v6.segments()[0] == 0x2001 && v6.segments()[1] == 0x0db8)
        }
    }
}

fn is_link_local(addr: IpAddr) -> bool {
    match addr {
        IpAddr::V4(v4) => v4.is_link_local(),
        IpAddr::V6(v6) => v6.segments()[0] & 0xffc0 == 0xfe80,
    }
}

/// Append `socket` unless it is already there. Two wildcards on one port expand into the same host
/// addresses, and a wildcard's loopback is the same socket a deliberate loopback bind names, so the
/// same address can be derived twice; the first derivation carries the reach, since a duplicate
/// cannot reach further than the entry already standing.
fn push_once(dialable: &mut Vec<At>, socket: SocketAddr, reach: Reach) {
    if !dialable.iter().any(|at| at.socket == socket) {
        dialable.push(At { socket, reach });
    }
}
