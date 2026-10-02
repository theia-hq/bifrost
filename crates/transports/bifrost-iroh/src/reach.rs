//! Who a node leans on to be reachable: the relay it offers as its home, and the service its
//! address record is published to and peers are resolved from.
//!
//! The two halves are independent, and each is n0's unless the caller names its own. A named half is
//! a URL a person typed, so it is parsed into a newtype here at the boundary ([`RelayUrl`],
//! [`ResolverUrl`]) and only then converted to the types iroh takes. iroh's own URL parse accepts any
//! scheme and its relay client speaks plaintext over `http://` and `ws://`, so the `https` pin has to
//! be this crate's: a plaintext hop puts every node id this endpoint reaches on the wire in the clear.

use core::fmt;
use core::str::FromStr;

use iroh::RelayMap;
use iroh::address_lookup::{
    AddressLookup, AddressLookupBuilder as _, AddressLookupBuilderError, PkarrPublisher,
    PkarrPublisherBuilder, PkarrResolver, PkarrResolverBuilder,
};
use iroh::endpoint::{Builder, RelayMode, default_relay_mode, presets};
use url::{Host, Url};

/// Where a bind goes for the two services a public key needs to be reachable. Both halves default to
/// n0's, which is what a bind that names no [`Reach`] gets.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Reach {
    /// The relay this node offers as its home relay, the address it publishes for peers that cannot
    /// reach it directly.
    pub relay: RelayHome,
    /// The service this node publishes its address record to and resolves peers from.
    pub resolver: Resolver,
}

impl Reach {
    /// The builder for a bind that takes on `role` over this reach.
    ///
    /// Every bind starts from `presets::Minimal`, which registers no lookup service and settles only
    /// the crypto provider, and adds each half explicitly, so no half silently inherits a service the
    /// preset gains later. The relay half is always a custom map, n0's included: iroh configures the
    /// relay transport the same from its default mode as from that mode's map, and a map is what a
    /// later swap on the bound endpoint diffs against.
    pub(crate) fn builder(&self, role: Role) -> Builder {
        let builder = iroh::Endpoint::builder(presets::Minimal)
            .relay_mode(RelayMode::Custom(self.relay.relays()));
        self.resolver.lookups(role).onto(builder)
    }
}

/// The relay a node offers as its home relay: n0's fleet, or one the caller runs.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum RelayHome {
    /// n0's relay fleet, the default.
    #[default]
    N0,
    /// A relay the caller runs, named by its origin.
    Custom(RelayUrl),
}

impl RelayHome {
    /// This home as the relay map iroh takes.
    pub(crate) fn relays(&self) -> RelayMap {
        match self {
            Self::N0 => default_relay_mode().relay_map(),
            // One URL is the whole map: a node offers exactly one home relay, and the relay a DIALER
            // uses comes from the peer's own record, never from this map.
            Self::Custom(RelayUrl(url)) => RelayMap::from(iroh::RelayUrl::from(Url::clone(url))),
        }
    }
}

/// The service a node publishes its address record to and resolves peers from: n0's, or one the
/// caller runs. Two nodes find each other only if they resolve through the same one.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum Resolver {
    /// n0's pkarr server, reached over https, the default.
    #[default]
    N0,
    /// A resolver the caller runs, named by its pkarr base.
    Custom(ResolverUrl),
}

impl Resolver {
    /// The lookup services an endpoint taking on `role` registers against this resolver.
    ///
    /// The n0 arm is `presets::N0` minus its DNS lookup, on purpose: that lookup asks the host's
    /// resolver, often plaintext on a shared network, for `_iroh.<key>`, which names every peer this
    /// node dials. The pkarr resolver asks the same n0 server over https, and wherever n0's relay is
    /// reachable so is that server, so dropping DNS costs no reach the relay keeps. A named resolver
    /// gets no DNS lookup either: a pkarr base is an HTTP path on one server, not a delegated DNS
    /// origin, so a DNS query against it would resolve nothing.
    pub(crate) fn lookups(&self, role: Role) -> Lookups {
        match self {
            Self::N0 => Lookups::of(PkarrPublisher::n0_dns(), PkarrResolver::n0_dns(), role),
            Self::Custom(ResolverUrl(base)) => Lookups::at(Url::clone(base), role),
        }
    }
}

/// The address lookup services an endpoint registers: a pkarr resolver, and a publisher beside it
/// when the endpoint serves under its key. Built here once so a bind and a swap on a bound endpoint
/// register the same services for the same resolver.
pub(crate) struct Lookups {
    publisher: Option<PkarrPublisherBuilder>,
    resolver: PkarrResolverBuilder,
}

impl Lookups {
    /// Publish to and resolve from the pkarr server at `base`.
    pub(crate) fn at(base: Url, role: Role) -> Self {
        Self::of(
            PkarrPublisher::builder(base.clone()),
            PkarrResolver::builder(base),
            role,
        )
    }

    fn of(publisher: PkarrPublisherBuilder, resolver: PkarrResolverBuilder, role: Role) -> Self {
        let publisher = match role {
            Role::Serving => Some(publisher),
            // A dialing endpoint drops the publisher and keeps the resolver: publishing under a key
            // another process is serving overwrites that node's record and sends peers to a dead path.
            Role::Dialing => None,
        };
        Self {
            publisher,
            resolver,
        }
    }

    /// Register these services on a bind.
    fn onto(self, builder: Builder) -> Builder {
        let Self {
            publisher,
            resolver,
        } = self;
        let builder = match publisher {
            Some(publisher) => builder.address_lookup(publisher),
            None => builder,
        };
        builder.address_lookup(resolver)
    }

    /// Start these services against a bound endpoint, ready to replace the ones it runs. Each is
    /// boxed because the publisher and the resolver are different types behind one trait.
    pub(crate) fn start(
        self,
        endpoint: &iroh::Endpoint,
    ) -> Result<Vec<Box<dyn AddressLookup>>, AddressLookupBuilderError> {
        let Self {
            publisher,
            resolver,
        } = self;
        let mut started: Vec<Box<dyn AddressLookup>> = Vec::with_capacity(2);
        if let Some(publisher) = publisher {
            started.push(Box::new(publisher.into_address_lookup(endpoint)?));
        }
        started.push(Box::new(resolver.into_address_lookup(endpoint)?));
        Ok(started)
    }
}

/// The origin of a relay, such as `https://relay.example`.
///
/// A relay URL carries no path: the relay client builds its own paths under the origin, so a path
/// here would be dropped without a word. Parse one with [`FromStr`], render it with [`Display`].
///
/// [`Display`]: fmt::Display
/// The URL is boxed so the newtype stays pointer-sized: a parsed `Url` is large by value, and these
/// travel inside command enums and argument structs in a consumer, where an inline one makes its
/// variant tower over the rest. A size test pins it so the indirection cannot be dropped by accident.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayUrl(Box<Url>);

impl FromStr for RelayUrl {
    type Err = ReachUrlError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let HttpsUrl(url) = text.parse()?;
        // The relay client builds the TLS name from the host as written, and an IPv6 literal carries
        // its brackets into that name, which no certificate can match: the bind would succeed and
        // every relay connect after it would die on the name.
        if matches!(url.host(), Some(Host::Ipv6(_))) {
            return Err(ReachUrlError::RelayIpv6);
        }
        // The relay client SETS its own path (`/relay`) on the origin, so a path typed here is
        // overwritten, never requested. Refuse it rather than swallow it.
        if url.path() != "/" {
            return Err(ReachUrlError::RelayPath {
                path: url.path().to_owned(),
            });
        }
        Ok(Self(Box::new(url)))
    }
}

impl fmt::Display for RelayUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self(url) = self;
        f.write_str(url.as_str())
    }
}

/// The pkarr base of a resolver, such as `https://dns.example/pkarr`.
///
/// The base keeps its path: a record is published and read at `<base>/<key>`. Parse one with
/// [`FromStr`], render it with [`Display`].
///
/// [`Display`]: fmt::Display
/// The URL is boxed so the newtype stays pointer-sized: a parsed `Url` is large by value, and these
/// travel inside command enums and argument structs in a consumer, where an inline one makes its
/// variant tower over the rest. A size test pins it so the indirection cannot be dropped by accident.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolverUrl(Box<Url>);

impl FromStr for ResolverUrl {
    type Err = ReachUrlError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let HttpsUrl(mut url) = text.parse()?;
        // The pkarr client appends the peer's key as a path segment, and appending keeps an existing
        // trailing slash, so `https://dns.example/pkarr/` would address `/pkarr//<key>` and miss. Drop
        // the one trailing slash at the parse, so what is stored is the form the client can extend.
        // An `https` URL is always a base, so the error arm is unreachable and leaves the path as is.
        if let Ok(mut segments) = url.path_segments_mut() {
            segments.pop_if_empty();
        }
        Ok(Self(Box::new(url)))
    }
}

impl fmt::Display for ResolverUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self(url) = self;
        f.write_str(url.as_str())
    }
}

/// A URL naming a relay or a resolver was refused. Each message names the fault and the fix, since a
/// caller shows it to the person who typed the URL.
#[derive(Debug, thiserror::Error)]
pub enum ReachUrlError {
    /// The text is not a URL at all.
    #[error("not a url: name a scheme and a host, e.g. https://relay.example")]
    Malformed(#[source] url::ParseError),
    /// The text carries a backslash, which reads as a path separator and moves the host boundary.
    #[error("a backslash in the url: write the host and the path with forward slashes only")]
    Backslash,
    /// The scheme is not `https`. A plaintext hop puts every key this node reaches on the wire in
    /// the clear, and a record published over one can be read and replaced in flight.
    #[error("only https is accepted, not {scheme}: name https://<host>")]
    NotHttps {
        /// The scheme that was named.
        scheme: String,
    },
    /// The host is a single DNS label. It resolves through whatever search domain the machine
    /// happens to carry, which is a different server on every network.
    #[error("{host} is not a fully qualified host: name the whole dns name, e.g. relay.example")]
    UnqualifiedHost {
        /// The host that was named.
        host: String,
    },
    /// The URL names port 0.
    #[error("port 0 cannot be dialed: name the port the server listens on, or drop it for 443")]
    ZeroPort,
    /// The URL carries credentials.
    #[error("credentials in the url are never sent: drop everything before the @")]
    Userinfo,
    /// The URL carries a query string.
    #[error("a query string is never sent: drop everything from the ? onward")]
    Query,
    /// The URL carries a fragment.
    #[error("a fragment is never sent: drop everything from the # onward")]
    Fragment,
    /// A relay URL names an IPv6 literal.
    #[error("a relay url cannot name an ipv6 literal: name the dns name the certificate carries")]
    RelayIpv6,
    /// A relay URL carries a path.
    #[error("a relay url takes no path: drop {path} and name just the host")]
    RelayPath {
        /// The path that was named.
        path: String,
    },
}

/// Which half of the record contract a bind takes on. It is the one difference between the two
/// builders, and an enum rather than a flag so a third kind of bind has to be decided here.
#[derive(Debug, Clone, Copy)]
pub(crate) enum Role {
    Serving,
    Dialing,
}

/// The invariants a relay origin and a resolver base share, parsed once so each public newtype adds
/// only its own path rule. Private: nobody holds one, it is the shared half of two [`FromStr`] impls.
struct HttpsUrl(Url);

impl FromStr for HttpsUrl {
    type Err = ReachUrlError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        // A backslash is a path separator for `https`, so `https://a\@b` parses to host `a` with
        // `/@b` as its path: the userinfo check below never fires and a reader scanning for the `@`
        // reads the wrong host. Refuse it in the raw text, before the parse moves the boundary.
        if text.contains('\\') {
            return Err(ReachUrlError::Backslash);
        }
        let url = Url::parse(text).map_err(ReachUrlError::Malformed)?;
        // https is the whole TLS pin: the relay client dials `http://` and `ws://` in the clear, and
        // the pkarr client would PUT a signed record over plaintext, so neither scheme may get in.
        // A URL parse of its own accord refuses an empty host for `https`, so a host is already here.
        if url.scheme() != "https" {
            return Err(ReachUrlError::NotHttps {
                scheme: url.scheme().to_owned(),
            });
        }
        // A single-label host is resolved through the machine's search domain, so the same URL names
        // a different server on every network. `domain` is `None` for an IP literal, which names one
        // host everywhere and is left to fail at the certificate check if it is not the right one.
        if let Some(domain) = url.domain().filter(|domain| !domain.contains('.')) {
            return Err(ReachUrlError::UnqualifiedHost {
                host: domain.to_owned(),
            });
        }
        // Neither client sends credentials, so a URL carrying them would drop them silently and leave
        // the caller believing the server is authenticated.
        if !url.username().is_empty() || url.password().is_some() {
            return Err(ReachUrlError::Userinfo);
        }
        // Port 0 is a parse-valid port that no connect can ever complete.
        if url.port() == Some(0) {
            return Err(ReachUrlError::ZeroPort);
        }
        // A query or a fragment is likewise dropped: the clients build their own request from the
        // origin and the path, so anything past them is a typo that would never reach the server.
        if url.query().is_some() {
            return Err(ReachUrlError::Query);
        }
        if url.fragment().is_some() {
            return Err(ReachUrlError::Fragment);
        }
        Ok(Self(url))
    }
}
