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
use std::collections::BTreeSet;
use std::io;

use if_addrs::Interface;

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
    /// Which class this scope belongs to: the same reach, with the instance dropped.
    ///
    /// [`Tunnel`](Self::Tunnel) is the only variant carrying one, so this is the whole difference
    /// between asking about the link `utun4` and asking about tunnels.
    pub fn class(&self) -> ScopeClass {
        match self {
            Self::Internet => ScopeClass::Internet,
            Self::Network => ScopeClass::Network,
            Self::Tunnel { .. } => ScopeClass::Tunnel,
            Self::ThisMachine => ScopeClass::ThisMachine,
        }
    }
}

/// How far a CLASS of address reaches: a [`Scope`] with the instance dropped, so every tunnel
/// rather than the one on `utun4`.
///
/// Consumers group by class rather than by scope: a surface renders one line per class, then asks
/// whether a class it drew nothing for is one that lost an address. Both questions are about the
/// class, and with no value for it each site can only ask by comparing discriminants, which is the
/// same question rewritten once per consumer. Naming it is also what lets a drop report say WHICH
/// class went short ([`Expiring::classes`]), so a consumer reads the classes that lost something
/// instead of sweeping all of them and asking about each.
///
/// Ordered as [`Dialable::all`] is ordered, by how far the class reaches without the peer first
/// joining something: anyone who can route to it, anyone on one named link, this machine. The
/// declaration order is the sort order, which is why it lives on the class and not on [`Scope`]:
/// an `Ord` on the scope would order two tunnels by link name and lose the interface order the OS
/// reported them in.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ScopeClass {
    /// The class of [`Scope::Internet`].
    Internet,
    /// The class of [`Scope::Network`].
    Network,
    /// The class of [`Scope::Tunnel`], whatever link an address of it sits on.
    Tunnel,
    /// The class of [`Scope::ThisMachine`].
    ThisMachine,
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
/// Built by [`of`](Self::of), which is TOTAL: whatever this host refuses to say, the set still
/// holds what is derivable without it (every concrete socket, and each wildcard's loopback) and
/// carries what went [`missing`](Self::missing), so a consumer renders a qualified list instead of
/// growing an error branch for a syscall.
#[derive(Debug)]
pub struct Dialable {
    /// The entries, in [`all`](Self::all)'s order.
    addrs: Vec<At>,
    /// What this host would not say, or would not still be answering on.
    missing: Missing,
}

impl Dialable {
    /// Expand `bound` into the sockets it answers on.
    ///
    /// The interface list is read only when a wildcard is actually present, so a bind that named its
    /// own addresses never pays the syscall and never misses anything: it answers at exactly the
    /// addresses it named, and nothing this host could say about any other one is a fact about it.
    pub fn of(bound: Vec<SocketAddr>) -> Self {
        if !bound.iter().any(|socket| socket.ip().is_unspecified()) {
            return Self {
                addrs: HostAddrs(Vec::new()).expand(bound),
                missing: Missing::Nothing,
            };
        }
        Self::of_host(HostAddrs::of_this_host(), bound)
    }

    /// Expand `bound` against the result of reading this host's interfaces.
    ///
    /// The seam [`of`](Self::of) is written over, so the failed-read half is exercised by a test
    /// that hands it the failure, and every other case by a test that hands it a fixed host.
    ///
    /// Where the read's [`Gaps`] become this set's [`Missing`]: only here are both facts in hand,
    /// the addresses the host would not stand behind and the bind that says which of them this set
    /// could ever have carried.
    pub(crate) fn of_host(
        host: Result<(HostAddrs, Gaps), io::Error>,
        bound: Vec<SocketAddr>,
    ) -> Self {
        match host {
            Ok((host, gaps)) => {
                // Narrowed before `bound` is spent on the expansion, since the same bind answers
                // both questions: which addresses become entries, and which losses are its own.
                let missing = gaps.against(&bound);
                Self {
                    addrs: host.expand(bound),
                    missing,
                }
            }
            // Total by construction: an empty interface list still expands a wildcard into the
            // loopback socket it genuinely answers on, and the cause rides along for the consumer
            // whose own outcome depends on it.
            Err(cause) => Self {
                addrs: HostAddrs(Vec::new()).expand(bound),
                missing: Missing::Interfaces(cause),
            },
        }
    }

    /// Assemble a set from entries already in hand that is MISSING something, and say what.
    ///
    /// [`FromIterator`] builds the set that read cleanly, which is the only set a consumer could
    /// build for itself; this builds the other ones. Without it, the branch a consumer writes over
    /// [`missing`](Self::missing) is a branch its own tests cannot reach, and a branch no test can
    /// reach is a branch that quietly goes missing. Handed [`Missing::Nothing`] it is
    /// [`FromIterator`], which is the constructor to reach for instead.
    ///
    /// What is missing is taken as given, never narrowed: there is no bind here to narrow it
    /// against, and entries already in hand are the whole expansion this set has.
    pub fn short(entries: impl IntoIterator<Item = At>, missing: Missing) -> Self {
        Self {
            missing,
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

    /// What this set does not carry: the one read that failed, or the addresses that were dropped
    /// because this host is about to stop answering on them.
    pub fn missing(&self) -> &Missing {
        &self.missing
    }

    /// Split into the entries and what went missing, for the one consumer that reports a missing
    /// interface list as its OWN outcome and so has to own the cause rather than borrow it.
    pub(crate) fn into_parts(self) -> (Vec<At>, Missing) {
        (self.addrs, self.missing)
    }
}

impl FromIterator<At> for Dialable {
    /// Assemble a set from entries already in hand, ordering them exactly as an expansion would.
    ///
    /// The order is [`all`](Dialable::all)'s invariant, so it is established here too rather than
    /// trusted from the caller: a value built this way is indistinguishable from an expanded one,
    /// which is what lets a consumer drive its own rendering over a host it does not have (a tunnel
    /// link, a second network address). Nothing was read, so nothing went missing:
    /// [`missing`](Dialable::missing) is [`Missing::Nothing`], and [`short`](Dialable::short) is
    /// how a caller says otherwise.
    fn from_iter<I: IntoIterator<Item = At>>(entries: I) -> Self {
        let mut addrs: Vec<At> = entries.into_iter().collect();
        addrs.sort_by_key(|at| at.scope.class());
        Self {
            addrs,
            missing: Missing::Nothing,
        }
    }
}

/// What a [`Dialable`] does not carry, so a surface can say in ONE read whether its list is short
/// and why, rather than promising a reach off a set that quietly lost half of itself.
///
/// Three things can go missing between a bind and its entries, and they are mutually exclusive by
/// construction: the interface list is read before the per-address flags, so a set that lost the
/// list never got as far as asking for the flags; and flags that could not be read drop nothing,
/// so a set that dropped something read them. One value, one cause, one arm to render.
#[derive(Debug)]
pub enum Missing {
    /// Nothing: every address this host reported, each one checked against its own flags.
    Nothing,
    /// This host's interface list, which the OS would not hand over, so every wildcard in the bind
    /// stands for its own loopback socket and nothing else. A consumer that renders these entries
    /// as this host's addresses without saying so asserts the host is loopback-only when it is not.
    Interfaces(io::Error),
    /// The per-address IPv6 flags, which this host would not report at all: a netlink socket a
    /// sandbox refuses to open is the live case, and a hardening line nobody would connect to
    /// address selection is all it takes. Every address is kept, so the list is WHOLE and
    /// unchecked rather than short, and one of the addresses in it may be an RFC 8981 temporary
    /// address that rots in the hand of the peer it is handed to. Reported only where that last
    /// sentence can be true, which is a bind that expands IPv6: the flags are IPv6's own, so a
    /// bind that expands no v6 wildcard is not short of them.
    Flags,
    /// The addresses this host reports it is about to stop answering on, dropped so a peer is never
    /// handed one that rots. Only the ones THIS bind would have expanded: see [`Gaps::against`].
    Expiring(Expiring),
}

/// The classes the addresses dropped as expiring came out of, each named once.
///
/// The class is the point, and it is the whole of it. A tally cannot be rendered: on a host that
/// never had a global address, a deprecated unique-local one is a drop that says nothing about the
/// internet, so only the CLASS a drop emptied tells an operator something they can act on. Two
/// drops out of one class are that one class, which is why this is a SET: the multiplicity answers
/// no question anyone may ask, and a shape that carries a fact nothing can render invites a
/// consumer to render it anyway. The addresses themselves are left out for the same reason and a
/// sharper one: the dropped address is the one privacy addressing exists to keep unpublished, and
/// handing it to a surface to print would defeat the mechanism that dropped it. A tunnel's link
/// name goes the same way.
///
/// Non-empty by construction: nothing dropped is [`Missing::Nothing`], never an empty report.
#[derive(Debug)]
pub struct Expiring(BTreeSet<ScopeClass>);

impl Expiring {
    /// The report for the scopes of the dropped addresses, or `None` when nothing was dropped.
    /// Each scope is kept as its [`class`](Scope::class) and no finer, and each class once.
    pub fn of(scopes: impl IntoIterator<Item = Scope>) -> Option<Self> {
        let classes: BTreeSet<ScopeClass> = scopes.into_iter().map(|scope| scope.class()).collect();
        (!classes.is_empty()).then_some(Self(classes))
    }

    /// Which classes lost an address, in [`Dialable::all`]'s order, which is what lets a consumer
    /// say WHICH class went short instead of only that something did.
    ///
    /// Handed over as classes rather than answered one class at a time, because the case that
    /// matters most is the one where nothing of that class is left: a link whose only address
    /// expired leaves no surviving row to read a link name off, so a question phrased as
    /// `Tunnel { link }` is one the consumer that needs the answer cannot even form. And a
    /// consumer asking which of the classes it drew nothing for was emptied only ever has to look
    /// at the classes something was dropped from, so these are all of them: sweeping every class
    /// instead is a fifth variant away from silently going unswept.
    pub fn classes(&self) -> impl Iterator<Item = ScopeClass> {
        self.0.iter().copied()
    }
}

/// What reading this host could not establish, before a bind says which of it matters.
///
/// [`Missing`] belongs to a SET, and the read that produces it holds only half of what it takes to
/// name: the host knows what it could not check and what it dropped, and only the bind knows which
/// address families it expands into entries. A v4-only bind on a dual-stack host never had a v6 row
/// to lose, so a v6 address dropped as expiring is not a loss that set can report: a consumer would
/// blame expiry for a row the BIND explains, and tell an operator to wait or renew over a family
/// this bind was never going to answer on. So the read's half travels this far as facts, and
/// becomes a [`Missing`] in [`Dialable::of_host`], where the bind is.
#[derive(Debug)]
pub(crate) enum Gaps {
    /// Nothing: every address this host reported, each one checked against its own flags.
    Nothing,
    /// The per-address IPv6 flags, which this host would not report at all. Says nothing about any
    /// one address: every address is kept and every one of them is unchecked. Narrowed by FAMILY
    /// all the same, because the flags it stands for are IPv6's alone: a bind that expands no v6
    /// wildcard carries no address this read could have checked, so it is short of nothing.
    Flags,
    /// The addresses this host reports it is about to stop answering on, already through the
    /// expansion's own policy and non-empty by construction, like the [`Expiring`] a bind narrows
    /// them into.
    Expiring(HostAddrs),
}

impl Gaps {
    /// The gap left by the interfaces the flag read took out of this host's list, and
    /// [`Nothing`](Self::Nothing) when it took none that would ever have been handed over.
    ///
    /// They go through the SAME policy the kept ones do, so a drop counts exactly when it would
    /// have become an entry: an address on a link that is down, or a link-local one, was never
    /// going to be handed to anyone, and reporting it as lost would send a consumer looking for a
    /// row that was never coming.
    pub(crate) fn expiring(dropped: Vec<Interface>) -> Self {
        let dropped = HostAddrs::of_interfaces(dropped);
        if dropped.0.is_empty() {
            return Self::Nothing;
        }
        Self::Expiring(dropped)
    }

    /// What a set expanded from `bound` is missing, which is less than this host could not say.
    ///
    /// A gap in a family `bound` never expands was never a candidate for an entry, so it is not
    /// this set's loss. A concrete socket answers at exactly itself and expands no family at all,
    /// which makes a bind of nothing but concrete sockets a bind no gap can be laid at: every
    /// address it answers on is one it named itself.
    ///
    /// ONE rule, both gaps, at the two scales each of them has. A drop is one address, so the
    /// narrowing asks the question of each dropped address and can leave nothing, and nothing left
    /// is [`Missing::Nothing`] rather than an empty report, which [`Expiring`] is not. Unread
    /// flags name no address, so the question is asked once for the whole family they cover: the
    /// platform reads collect IPv6 addresses and nothing else, so a v4-only bind (any
    /// transport that binds `0.0.0.0` alone) would otherwise carry a permanent caveat about
    /// an expiry that could not touch a single row it renders.
    fn against(self, bound: &[SocketAddr]) -> Missing {
        match self {
            Self::Nothing => Missing::Nothing,
            Self::Flags if expands_family_of(bound, IpAddr::V6(Ipv6Addr::UNSPECIFIED)) => {
                Missing::Flags
            }
            Self::Flags => Missing::Nothing,
            Self::Expiring(dropped) => {
                Expiring::of(dropped.expanded_by(bound).map(|addr| addr.scope))
                    .map_or(Missing::Nothing, Missing::Expiring)
            }
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
    /// Read this host's live interfaces, and what the read could not establish about them.
    ///
    /// Two reads, not one. `if-addrs` reports an interface's flags but never an ADDRESS's, and an
    /// IPv6 interface routinely carries a stable address and an RFC 8981 temporary one that is
    /// indistinguishable from it by its bits alone. Asking the platform for those flags is the
    /// only way to tell them apart, so it happens HERE, against the live list, and the policy
    /// below stays a pure function of whatever list it is handed.
    ///
    /// Each read can come up empty in its own way, and both ways travel with the result: a list
    /// this host would not hand over is the error, and flags it would not report, or addresses it
    /// reported as expiring, are the [`Gaps`] beside the addresses that survived. Gaps and not
    /// [`Missing`]: which of them a SET is short of is a question only its bind can answer.
    fn of_this_host() -> Result<(Self, Gaps), io::Error> {
        let interfaces = if_addrs::get_if_addrs()?;
        let (kept, lifetimes) = stable::sift(interfaces);
        let gaps = match lifetimes {
            stable::Lifetimes::Unread => Gaps::Flags,
            stable::Lifetimes::Expiring(dropped) => Gaps::expiring(dropped),
        };
        Ok((Self::of_interfaces(kept), gaps))
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
        dialable.sort_by_key(|at| at.scope.class());
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

    /// These addresses that `bound` as a whole expands: the set-level form of
    /// [`same_family`](Self::same_family)'s per-wildcard question, filtered the same way, so the
    /// two cannot come to disagree about which addresses a bind stands for.
    ///
    /// An address is expanded when SOME wildcard in the bind stands for its family, and a concrete
    /// socket stands for no family at all, since it answers at exactly the address it named. Each
    /// address is yielded at most once however many wildcards match it, so two wildcards of one
    /// family on different ports do not make one lost address read as two.
    pub(crate) fn expanded_by(self, bound: &[SocketAddr]) -> impl Iterator<Item = HostAddr> {
        self.0
            .into_iter()
            .filter(move |host| expands_family_of(bound, host.ip) && !is_link_local(host.ip))
    }
}

/// Whether some wildcard in `bound` stands for the family `family` is in.
///
/// The one definition of what a bind expands, which is asked at two scales: of one of this host's
/// addresses, to say whether it could ever have become an entry, and of a family as a whole, to
/// say whether a read covering only that family is a read this bind needed. A concrete socket
/// expands nothing and is never a match: it answers at exactly the address it named.
fn expands_family_of(bound: &[SocketAddr], family: IpAddr) -> bool {
    bound
        .iter()
        .any(|socket| socket.ip().is_unspecified() && socket.ip().is_ipv4() == family.is_ipv4())
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
        // IETF protocol assignments (`2001::/23`), the whole block IANA marks not globally
        // reachable: Teredo (`2001::/32`), benchmarking (`2001:2::/48`), AMT (`2001:3::/32`),
        // AS112 (`2001:4:112::/48`), ORCHID (`2001:10::/28`) and ORCHIDv2 (`2001:20::/28`). One
        // arm for all of them, because the block is reserved wholesale and naming each assignment
        // is a list that goes stale every time the IETF takes another one.
        [0x2001, 0x0000..=0x01ff, ..]
        // Documentation (`2001:db8::/32`), which sits outside the block above.
        | [0x2001, 0x0db8, ..]
        // 6to4 (`2002::/16`): reachable only through a relay, and one derived from an RFC 1918 v4
        // address reads exactly like one derived from a routable address.
        | [0x2002, ..]
        // Documentation (`3fff::/20`, RFC 9637), the range that replaced borrowing a real prefix
        // for an example.
        | [0x3fff, 0x0000..=0x0fff, ..]
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
