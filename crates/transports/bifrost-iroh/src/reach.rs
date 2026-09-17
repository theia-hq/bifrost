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
use iroh::address_lookup::{DnsAddressLookup, PkarrPublisher, PkarrResolver};
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
    /// The builder for a bind that PUBLISHES this node's address record, so peers find it by key.
    pub(crate) fn serving(self) -> Builder {
        self.apply(Role::Serving)
    }

    /// The builder for a bind that only RESOLVES other nodes' records and writes none of its own.
    pub(crate) fn dialing(self) -> Builder {
        self.apply(Role::Dialing)
    }

    /// Every bind starts from `presets::Minimal`, which registers no lookup service and settles only
    /// the crypto provider, and adds each half explicitly. The n0 arms reproduce exactly what
    /// `presets::N0` registers (the pkarr publisher, the pkarr resolver, the DNS lookup, and the
    /// default relay mode), so an n0 half is byte for byte what it has always been while a named half
    /// never silently inherits a service the preset gains later.
    fn apply(self, role: Role) -> Builder {
        let Self { relay, resolver } = self;
        let relay_mode = match relay {
            RelayHome::N0 => default_relay_mode(),
            // One URL is the whole map: a node offers exactly one home relay, and the relay a DIALER
            // uses comes from the peer's own record, never from this map.
            RelayHome::Custom(RelayUrl(url)) => {
                RelayMode::Custom(RelayMap::from(iroh::RelayUrl::from(*url)))
            }
        };
        let builder = iroh::Endpoint::builder(presets::Minimal).relay_mode(relay_mode);

        match (resolver, role) {
            (Resolver::N0, Role::Serving) => builder
                .address_lookup(PkarrPublisher::n0_dns())
                .address_lookup(PkarrResolver::n0_dns())
                .address_lookup(DnsAddressLookup::n0_dns()),
            // A dialing bind drops the publisher and keeps both resolvers: publishing under a key
            // another process is serving overwrites that node's record and sends peers to a dead path.
            (Resolver::N0, Role::Dialing) => builder
                .address_lookup(PkarrResolver::n0_dns())
                .address_lookup(DnsAddressLookup::n0_dns()),
            // A named resolver gets no DNS lookup: a pkarr base is an HTTP path on one server, not a
            // delegated DNS origin, so a DNS query against it would resolve nothing.
            (Resolver::Custom(ResolverUrl(base)), Role::Serving) => builder
                .address_lookup(PkarrPublisher::builder(Url::clone(&base)))
                .address_lookup(PkarrResolver::builder(*base)),
            (Resolver::Custom(ResolverUrl(base)), Role::Dialing) => {
                builder.address_lookup(PkarrResolver::builder(*base))
            }
        }
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

/// The service a node publishes its address record to and resolves peers from: n0's, or one the
/// caller runs. Two nodes find each other only if they resolve through the same one.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum Resolver {
    /// n0's pkarr and DNS servers, the default.
    #[default]
    N0,
    /// A resolver the caller runs, named by its pkarr base.
    Custom(ResolverUrl),
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
#[derive(Debug)]
enum Role {
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
