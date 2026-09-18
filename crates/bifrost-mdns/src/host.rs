//! Turning bind truth into the concrete sockets a bind answers on, each carrying how far it reaches.
//!
//! The input is bind truth (`bifrost::Transport::bound_sockets`): the sockets as bound, with an
//! unspecified IP preserved. A concrete socket answers at itself; a wildcard answers at every
//! interface address of its family, and at loopback. That expansion is the only code in the family
//! that turns a bind into addresses, and it has two consumers with genuinely different rules: this
//! crate's advertiser, which may publish only what a peer hearing a multicast query could dial, and a
//! surface that hands an operator addresses to pass to a peer by hand. So the scope of each address
//! is a FACT the entry carries, and each consumer applies its own rule to it, rather than one
//! consumer reading the other's filtered result.

use core::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use if_addrs::Interface;

use crate::MdnsError;

mod stable;

/// How far an address this bind answers on can be routed from.
///
/// Not a ranking of quality: which entry is right depends on where the peer is, and nothing on this
/// host knows that. It is who can route to the address, which is what a consumer needs to decide
/// whether it may publish the address, and what a surface needs to mark it with.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Scope {
    /// A globally routable address: a peer anywhere on the internet can route to it, given a path.
    /// The only class that reaches a peer who is not already on a network or an overlay with this
    /// host, which on a transport with no relay and no NAT traversal is the only way to reach one
    /// at all.
    Internet,
    /// A link with a network behind it, and that network is where it stops: a private or
    /// unique-local address reaches a peer on this network and no further. Distinct from
    /// [`Internet`](Self::Internet) because the two look alike and do not behave alike, and a line
    /// that did not say which claimed the wider scope for both.
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

impl Scope {
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
    pub scope: Scope,
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

    /// Assemble a set from entries already in hand that is SHORT, and say why.
    ///
    /// [`FromIterator`] builds the set that read cleanly, which is the only set a consumer could
    /// build for itself; this builds the other one. Without it, the branch a consumer writes over
    /// [`interfaces`](Self::interfaces) is a branch its own tests cannot reach, and a branch no
    /// test can reach is a branch that quietly goes missing.
    pub fn short(entries: impl IntoIterator<Item = At>, cause: MdnsError) -> Self {
        Self {
            interfaces: Some(cause),
            ..Self::from_iter(entries)
        }
    }

    /// Every socket this bind answers on: [`Internet`] first, then [`Network`], then [`Tunnel`],
    /// then [`ThisMachine`], each group in the order the host reported its interfaces.
    ///
    /// [`Internet`]: Scope::Internet
    /// [`Network`]: Scope::Network
    /// [`Tunnel`]: Scope::Tunnel
    /// [`ThisMachine`]: Scope::ThisMachine
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
    /// [`interfaces`](Dialable::interfaces) is `None`, and [`short`](Dialable::short) is how a
    /// caller says otherwise.
    fn from_iter<I: IntoIterator<Item = At>>(entries: I) -> Self {
        let mut addrs: Vec<At> = entries.into_iter().collect();
        addrs.sort_by_key(|at| at.scope.rank());
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
    pub(crate) scope: Scope,
}

impl HostAddrs {
    /// Read this host's live interfaces.
    ///
    /// Two reads, not one. `if-addrs` reports an interface's flags but never an ADDRESS's, and an
    /// IPv6 interface routinely carries a stable address and an RFC 8981 temporary one that is
    /// indistinguishable from it by its bits alone. Asking the platform for those flags is the
    /// only way to tell them apart, so it happens HERE, against the live list, and the policy
    /// below stays a pure function of whatever list it is handed.
    fn of_this_host() -> Result<Self, MdnsError> {
        let interfaces = if_addrs::get_if_addrs().map_err(MdnsError::Interfaces)?;
        Ok(Self::of_interfaces(stable::only(interfaces)))
    }

    /// The addresses of the interfaces a wildcard bind answers on, each with its scope.
    ///
    /// Two kinds of interface are left out, because an address taken from one is an address NEITHER
    /// consumer can use. An interface the OS does not report as running is not one this node answers
    /// on, and naming it costs a dialing peer a timeout. A link-local address means nothing without
    /// the scope of the interface it came from, which neither a record nor a pasted address carries.
    /// A point-to-point link (utun, tun, wg, a tailnet) is NOT dropped: the socket observably answers
    /// there, so the fact that the link has no network behind it is carried as [`Scope::Tunnel`] and
    /// left to each consumer, which is what stops one consumer's publication policy from deciding
    /// what the other may hand a human. An address that is about to expire is dropped one step
    /// earlier, in [`of_this_host`](Self::of_this_host), which is where the flags for it exist.
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
                    scope: if interface.ip().is_loopback() {
                        Scope::ThisMachine
                    } else if interface.is_p2p() {
                        Scope::Tunnel {
                            link: interface.name,
                        }
                    } else if is_globally_routable(interface.ip()) {
                        Scope::Internet
                    } else {
                        Scope::Network
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
    ///
    /// A concrete address is scoped by the ADDRESS alone, because there is no interface list to
    /// match it against and so no link to ask: a concrete bind on a tunnel address reads as
    /// [`Scope::Network`], never [`Scope::Tunnel`]. Nothing binds one today, and inventing a
    /// syscall to sharpen a case nobody has would buy nothing; the caller that starts binding
    /// tunnel addresses concretely is the one that should.
    pub(crate) fn expand(&self, bound: Vec<SocketAddr>) -> Vec<At> {
        let mut dialable: Vec<At> = Vec::with_capacity(bound.len());
        for socket in bound {
            if !socket.ip().is_unspecified() {
                let scope = if socket.ip().is_loopback() {
                    Scope::ThisMachine
                } else if is_globally_routable(socket.ip()) {
                    Scope::Internet
                } else {
                    Scope::Network
                };
                push_once(&mut dialable, socket, scope);
                continue;
            }
            for host in self.same_family(socket.ip()) {
                push_once(
                    &mut dialable,
                    SocketAddr::new(host.ip, socket.port()),
                    host.scope.clone(),
                );
            }
            // The wildcard's own loopback socket, whether or not the interface list named one (it
            // does not when the read failed): a wildcard bind answers there, and for an isolated
            // host it is the only address it answers on at all.
            push_once(
                &mut dialable,
                SocketAddr::new(loopback_of(socket.ip()), socket.port()),
                Scope::ThisMachine,
            );
        }
        // Stable, so the interface order the OS reported survives inside each group.
        dialable.sort_by_key(|at| at.scope.rank());
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

/// Whether `addr` is one a peer anywhere on the internet could route to, given a path.
///
/// Spelled out rather than taken from the standard library: the `is_global` family is still
/// unstable, and the shape this needs is narrow enough that naming the ranges is clearer than
/// waiting for it. Asked only AFTER the loopback and point-to-point tests, so a tunnel address
/// whose range happens to read one way is already classified by its link, which is better evidence.
///
/// v4: everything that is not reserved for somewhere smaller than the internet. v6: the single
/// global-unicast prefix `2000::/3`, which is what a routable v6 address is by definition and which
/// excludes unique-local `fc00::/7` and link-local `fe80::/10` without naming them, minus the
/// ranges that sit INSIDE it and are reserved rather than routable.
fn is_globally_routable(addr: IpAddr) -> bool {
    match addr {
        IpAddr::V4(v4) => {
            !v4.is_private()
                && !v4.is_loopback()
                && !v4.is_link_local()
                && !v4.is_multicast()
                && !v4.is_documentation()
                && !is_reserved_v4(v4)
        }
        IpAddr::V6(v6) => v6.segments()[0] & 0xe000 == 0x2000 && !is_reserved_v6(v6),
    }
}

/// The v4 ranges reserved for something other than the open internet that the standard library has
/// no STABLE predicate for: `is_shared`, `is_benchmarking` and `is_reserved` are all unstable, so
/// each is named here instead of waiting for them.
///
/// Two of these subsume a predicate the caller would otherwise ask separately for: `240.0.0.0/4`
/// covers the broadcast address, and `0.0.0.0/8` covers the unspecified one.
fn is_reserved_v4(addr: Ipv4Addr) -> bool {
    matches!(
        addr.octets(),
        // This network (`0.0.0.0/8`): a source-only range, and `0.0.0.0` itself.
        [0, ..]
        // Carrier-grade NAT (`100.64.0.0/10`): a provider's own space, and the range a tailnet
        // hands out, so an overlay address that escaped the link test still does not read as
        // internet-routable.
        | [100, 64..=127, ..]
        // IETF protocol assignments (`192.0.0.0/24`), including the NAT64 well-known prefix.
        | [192, 0, 0, _]
        // 6to4 relay anycast (`192.88.99.0/24`), deprecated and never a host address.
        | [192, 88, 99, _]
        // Benchmarking (`198.18.0.0/15`). The live one: Zscaler, Umbrella and WARP hand these out
        // on their virtual interfaces, where no link test catches them.
        | [198, 18..=19, ..]
        // Reserved for future use (`240.0.0.0/4`), broadcast included.
        | [240..=255, ..]
    )
}

/// The v6 ranges that sit inside global unicast `2000::/3` and are reserved rather than routable.
/// `Ipv6Addr::is_global` is unstable and `is_documentation` with it, so each is named here.
fn is_reserved_v6(addr: Ipv6Addr) -> bool {
    matches!(
        addr.segments(),
        // Teredo (`2001::/32`): a tunnel endpoint, not an address of this host's own.
        [0x2001, 0x0000, ..]
        // Benchmarking (`2001:2::/48`).
        | [0x2001, 0x0002, 0x0000, ..]
        // ORCHIDv2 (`2001:20::/28`): cryptographic identifiers, never routed.
        | [0x2001, 0x0020..=0x002f, ..]
        // Documentation (`2001:db8::/32`).
        | [0x2001, 0x0db8, ..]
        // 6to4 (`2002::/16`): reachable only through a relay, and one derived from an RFC 1918 v4
        // address reads exactly like one derived from a routable address.
        | [0x2002, ..]
    )
}

/// Whether `addr` is link-local: `169.254.0.0/16`, or `fe80::/10` matched by its prefix because
/// `Ipv6Addr` has no stable accessor for it.
fn is_link_local(addr: IpAddr) -> bool {
    match addr {
        IpAddr::V4(v4) => v4.is_link_local(),
        IpAddr::V6(v6) => v6.segments()[0] & 0xffc0 == 0xfe80,
    }
}

/// Append `socket` unless it is already there. Two wildcards on one port expand into the same host
/// addresses, and a wildcard's loopback is the same socket a deliberate loopback bind names, so the
/// same address can be derived twice; the first derivation carries the scope, since a duplicate
/// cannot reach further than the entry already standing.
fn push_once(dialable: &mut Vec<At>, socket: SocketAddr, scope: Scope) {
    if !dialable.iter().any(|at| at.socket == socket) {
        dialable.push(At { socket, scope });
    }
}
