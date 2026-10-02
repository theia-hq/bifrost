//! iroh-backed implementation of the Bifrost transport interface.
//!
//! iroh does the hard parts (QUIC, NAT traversal, relay fallback, raw-public-key TLS) so a session
//! to a [`NodeId`] works across the internet. This crate maps iroh's endpoint, connection, and
//! streams onto the [`Transport`] and [`Session`] traits, and keeps iroh's own address type from
//! leaking past this boundary.

use core::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use core::pin::Pin;
use core::task::{Context, Poll, ready};
use core::time::Duration;
use std::sync::Arc;

pub use bifrost_core::NodeId;
use bifrost_core::{
    Addr, BoxError, ConnInfo, CryptoKind, Error, HintStream, KeyError, Path, PathChanges, Relay,
};
pub use bifrost_transport::{Sealed, Session, Transport};
use futures_core::Stream;
use iroh::address_lookup::AddressLookupBuilderError;
use iroh::endpoint::{
    Connection, PathEvent, PathEventStream, PathList, PortmapperConfig, RecvStream, RelayMode,
    SendStream, WeakConnectionHandle, presets,
};
use iroh::{EndpointAddr, EndpointId, PublicKey, RelayMap, SecretKey, TransportAddr};
use tokio::sync::Mutex;
use url::Url;
use zeroize::Zeroizing;

mod reach;

use reach::{Lookups, Role};
pub use reach::{Reach, ReachUrlError, RelayHome, RelayUrl, Resolver, ResolverUrl};

/// The ALPN that identifies the Bifrost substrate protocol during the handshake.
pub const ALPN: &[u8] = b"bifrost/0";

/// A bound iroh endpoint.
///
/// A clone is a second handle on the same endpoint, not a second endpoint: it shares the socket, the
/// identity and the reach, so a [`set_reach`](Self::set_reach) through one is what every clone reads
/// back, and a close through one closes them all.
#[derive(Clone)]
pub struct Endpoint {
    inner: iroh::Endpoint,
    /// This endpoint's own identity, derived once at bind from the secret it binds under.
    node: NodeId,
    /// How this bind finds a peer, which decides whether a dial waits on a discovery feed.
    finding: Finding,
    /// The reach this endpoint runs on, or `None` for a local or offline bind, which has no relay
    /// and no resolver to change. Behind an async lock held across a whole swap: two swaps that
    /// interleaved their relay inserts and removes would leave a map that is neither one.
    reach: Option<Arc<Mutex<Applied>>>,
}

/// The reach a bind or the last swap put on an endpoint.
struct Applied {
    reach: Reach,
    /// Fixed at bind: a dialing endpoint never starts publishing because its reach changed.
    role: Role,
    /// The URLs of the relay map as applied, which the next swap diffs against. Kept here because
    /// iroh does not read its relay map back. Never fewer than iroh's map holds: a swap records each
    /// URL before it inserts it and forgets it only as it removes it, so a swap cancelled at any
    /// await leaves nothing in the map that the next swap would not see and remove.
    relays: Vec<iroh::RelayUrl>,
    /// The map handed to iroh at bind, which iroh keeps and edits in place. Read only by tests, to
    /// check what a swap did to the live map rather than infer it from timing.
    #[cfg(test)]
    live: RelayMap,
}

/// How an endpoint finds a peer, fixed by the bind that made it.
///
/// A bind fact rather than a transport fact: the same iroh endpoint type finds peers by key under
/// an n0-shaped bind and only by hints under a minimal or offline one, so no single answer could be
/// declared for the type.
#[derive(Debug, Clone, Copy)]
enum Finding {
    /// The bind registered an address lookup (pkarr) and relays, so iroh finds a peer by its
    /// key on its own. A dial never waits on a feed; it takes only what the feed already holds at
    /// that instant (a hint the caller supplied, a LAN record already heard).
    ByKey,
    /// A minimal or offline bind with no lookup of its own: a peer is reachable only through hints,
    /// so a dial waits for the feed's first answer.
    ByHints,
}

impl Finding {
    /// The address a dial under this bind goes with: the one read of the feed the bind allows.
    ///
    /// Kept apart from the dial so the choice is testable without a network: only the dial after it
    /// touches iroh. Both arms read the feed once and drop it, since iroh at this version takes no
    /// addresses into an attempt already running.
    async fn seed(self, addr: Addr, updates: HintStream) -> Result<Addr, Error> {
        match self {
            // Found by key: what the feed holds at this instant (a caller's hint, a LAN record
            // already heard), and never a wait for more, since iroh can find the peer without it.
            Self::ByKey => addr.seeded(updates.ready()),
            // Found only by hints: a dial with none has nothing to go to, so it waits for the
            // feed's first answer, bounded by whoever awaits the dial.
            Self::ByHints => addr.seeded(updates.first().await),
        }
    }
}

impl Endpoint {
    /// Bind with a fresh identity, using n0 discovery and relays so it is reachable by [`NodeId`]
    /// across NATs. The fresh-identity reachable shape: it publishes a record under a key generated per
    /// call that no dialer holds, like [`bind_reachable_with_secret`](Self::bind_reachable_with_secret).
    pub async fn bind() -> Result<Self, BindError> {
        Self::finish_via(Reach::default(), Role::Serving, SecretKey::generate()).await
    }

    /// Bind with a persisted identity as a SERVING node: n0 discovery and relays, and publish this
    /// endpoint's address record (n0 pkarr/DNS) so peers reach it by key. The serving bind: bind this
    /// only from the process that accepts connections under the key.
    ///
    /// Every persisted-identity bind here borrows the secret and turns it into the endpoint's key
    /// before it returns; the future it returns holds that key, not the borrow. So a caller holding
    /// the secret in a wiping owner binds with `secret.with_bytes(Endpoint::bind_..)` and makes no
    /// copy of it.
    pub fn bind_reachable_with_secret(
        secret: &[u8; 32],
    ) -> impl Future<Output = Result<Self, BindError>> + use<> {
        Self::bind_reachable_with_secret_via(secret, Reach::default())
    }

    /// Bind with a persisted identity for DIALING ONLY: n0 resolution and relays, no address record.
    /// A dialer is not reachable at its key; publishing here overwrites whatever process IS serving
    /// that key (the 0.9.0 F1 finding: a short-lived command wrote its own relay, exited, and dialers
    /// followed a dead relay path). What n0 registers, minus its `PkarrPublisher`.
    pub fn bind_dialing_with_secret(
        secret: &[u8; 32],
    ) -> impl Future<Output = Result<Self, BindError>> + use<> {
        Self::bind_dialing_with_secret_via(secret, Reach::default())
    }

    /// Bind as a SERVING node over a caller-named [`Reach`]: the same publish-my-record bind as
    /// [`bind_reachable_with_secret`](Self::bind_reachable_with_secret), with the relay and the
    /// resolver each either n0's or one the caller runs.
    pub fn bind_reachable_with_secret_via(
        secret: &[u8; 32],
        reach: Reach,
    ) -> impl Future<Output = Result<Self, BindError>> + use<> {
        Self::finish_via(reach, Role::Serving, SecretKey::from_bytes(secret))
    }

    /// Bind for DIALING ONLY over a caller-named [`Reach`]: the same no-record bind as
    /// [`bind_dialing_with_secret`](Self::bind_dialing_with_secret), with the relay and the resolver
    /// each either n0's or one the caller runs. A dialer must resolve through the same resolver as
    /// the node it is looking for, or that node's record is not there to find.
    pub fn bind_dialing_with_secret_via(
        secret: &[u8; 32],
        reach: Reach,
    ) -> impl Future<Output = Result<Self, BindError>> + use<> {
        Self::finish_via(reach, Role::Dialing, SecretKey::from_bytes(secret))
    }

    /// Bind a local-only endpoint with a FRESH identity, for same-process tests (the conformance
    /// suite): no discovery, no relays, no fixed address. A node that must keep one address across
    /// runs binds [`bind_local_with_secret`](Self::bind_local_with_secret) instead.
    pub async fn bind_local() -> Result<Self, BindError> {
        Self::finish(
            iroh::Endpoint::builder(presets::Minimal),
            SecretKey::generate(),
            Finding::ByHints,
            None,
        )
        .await
    }

    /// Bind a local-only endpoint with a PERSISTED identity: no n0 discovery, no relays, no
    /// portmapper, on an OS-assigned port. Reachable only by direct address hints or the local
    /// discovery composed above, and the same key yields the same [`NodeId`] across runs.
    pub fn bind_local_with_secret(
        secret: &[u8; 32],
    ) -> impl Future<Output = Result<Self, BindError>> + use<> {
        Self::finish(
            iroh::Endpoint::builder(presets::Minimal)
                // `presets::Minimal` leaves both of these at the iroh defaults (relays on, portmapper
                // enabled). Pin them off explicitly so "no NAT traversal" is configuration, not an
                // accident of an empty relay map or a future preset change.
                .relay_mode(RelayMode::Disabled)
                .portmapper_config(PortmapperConfig::Disabled),
            SecretKey::from_bytes(secret),
            Finding::ByHints,
            None,
        )
    }

    /// Bind an OFFLINE endpoint: a persisted identity, no n0 discovery and no relays, at a fixed local
    /// address. Reachable ONLY via direct address hints, so two nodes on a LAN or a Docker
    /// network connect directly with nothing crossing the internet. The fixed port is what makes the
    /// address hardcodable: a peer names `host:port` and reaches it, no discovery service in the loop.
    pub fn bind_offline(
        secret: &[u8; 32],
        bind_addr: SocketAddr,
    ) -> impl Future<Output = Result<Self, BindError>> + use<> {
        let secret = SecretKey::from_bytes(secret);
        async move {
            Self::finish(
                iroh::Endpoint::builder(presets::Minimal).bind_addr(bind_addr)?,
                secret,
                Finding::ByHints,
                None,
            )
            .await
        }
    }

    /// Point this bound endpoint at `reach`: the relay it offers as its home, and the resolver it
    /// resolves peers through and, if it was bound to serve, publishes its record to. Needs no rebind,
    /// and open connections stay open.
    ///
    /// A return means the reach is applied, but the home relay may not have moved yet. iroh picks the
    /// home relay from its next network report over the new relays, and when that report reaches none
    /// of them, iroh keeps the old home in use though it is no longer in the map. A resolver change replaces the old lookups
    /// with the new ones, so a resolve in the instant between finds nothing, and a record already
    /// published to the old resolver stays there until its TTL runs out. A swap that keeps the
    /// resolver keeps the lookups running.
    ///
    /// Cancel-safe: a call dropped before it returns leaves [`reach`](Self::reach) and the resolver as
    /// they were, though some relays may already be swapped; the next call sets the relays to its own.
    ///
    /// # Errors
    ///
    /// [`SetReachError::Local`] on an endpoint from a local or offline bind,
    /// [`SetReachError::Closed`] once the endpoint is closed, and [`SetReachError::Lookup`] when the
    /// new resolver's lookups cannot start, which a closed endpoint can also cause. The reach read
    /// back by [`reach`](Self::reach) changes only when the swap succeeds.
    pub async fn set_reach(&self, reach: Reach) -> Result<(), SetReachError> {
        let Some(applied) = &self.reach else {
            return Err(SetReachError::Local);
        };
        let mut applied = applied.lock().await;
        let lookups = (applied.reach.resolver != reach.resolver)
            .then(|| reach.resolver.lookups(applied.role));
        self.swap(&mut applied.relays, &reach.relay.relays(), lookups)
            .await?;
        applied.reach = reach;
        Ok(())
    }

    /// The reach this endpoint was last pointed at, by its bind or by
    /// [`set_reach`](Self::set_reach), or `None` for a local or offline bind. What was applied, not
    /// which relay is in use: see [`set_reach`](Self::set_reach).
    pub async fn reach(&self) -> Option<Reach> {
        Some(self.reach.as_ref()?.lock().await.reach.clone())
    }

    /// Replace the relays in `applied` with `relays`, and the lookups with `lookups` when given.
    async fn swap(
        &self,
        applied: &mut Vec<iroh::RelayUrl>,
        relays: &RelayMap,
        lookups: Option<Lookups>,
    ) -> Result<(), SetReachError> {
        // Both fallible steps come before any change, so an error leaves the endpoint as it was.
        let services = self
            .inner
            .address_lookup()
            .map_err(|_closed| SetReachError::Closed)?;
        let started = lookups
            .map(|lookups| lookups.start(&self.inner))
            .transpose()
            .map_err(SetReachError::Lookup)?;

        // Insert before removing, so the map is never empty in between: an empty map gives the
        // network report no relay to pick a home from. Each edit lands in iroh's map on its first
        // poll, before its await can yield, so `applied` is updated just ahead of it: a swap
        // cancelled at any await leaves `applied` holding every URL the map holds, and the next swap
        // removes whatever this one left behind.
        let next: Vec<iroh::RelayUrl> = relays.urls();
        for config in relays.relays::<Vec<_>>() {
            if !applied.contains(&config.url) {
                applied.push(config.url.clone());
                self.inner.insert_relay(config.url.clone(), config).await;
            }
        }
        let gone: Vec<iroh::RelayUrl> = applied
            .iter()
            .filter(|url| !next.contains(url))
            .cloned()
            .collect();
        for url in gone {
            applied.retain(|kept| *kept != url);
            self.inner.remove_relay(&url).await;
        }

        // No await from here on, so the lookups change whole or not at all. A swap cancelled before
        // this point leaves the reach unrecorded, so the next swap compares against the old resolver
        // and replaces the lookups then.
        if let Some(started) = started {
            // iroh offers no swap of one service for another, so this clears and adds. `add`
            // republishes the last published record at once, so the new resolver holds it without
            // waiting for the next change of address.
            services.clear();
            for service in started {
                services.add_boxed(service);
            }
        }
        Ok(())
    }

    /// Bind over `reach` as `role`, remembering both so the reach can be changed later.
    fn finish_via(
        reach: Reach,
        role: Role,
        secret: SecretKey,
    ) -> impl Future<Output = Result<Self, BindError>> + use<> {
        let relays = reach.relay.relays();
        let urls = relays.urls();
        #[cfg(test)]
        let live = relays.clone();
        let builder = reach.builder(role, relays);
        let applied = Applied {
            relays: urls,
            #[cfg(test)]
            live,
            reach,
            role,
        };
        Self::finish(
            builder,
            secret,
            Finding::ByKey,
            Some(Arc::new(Mutex::new(applied))),
        )
    }

    async fn finish(
        builder: iroh::endpoint::Builder,
        secret: SecretKey,
        finding: Finding,
        reach: Option<Arc<Mutex<Applied>>>,
    ) -> Result<Self, BindError> {
        // Derived from the secret, not parsed from iroh's id: a secret's public half is a canonical
        // prime-order point, so the own id has nothing to refuse. The copy of the secret is wiped here.
        let node = NodeId::from_ed25519_secret(&Zeroizing::new(secret.to_bytes()));
        let inner = builder
            .secret_key(secret)
            .alpns(vec![ALPN.to_vec()])
            .bind()
            .await?;
        Ok(Self {
            inner,
            node,
            finding,
            reach,
        })
    }
}

impl Transport for Endpoint {
    type Security = Sealed;
    type Session = IrohSession;

    fn node_id(&self) -> NodeId {
        self.node
    }

    fn local_addr(&self) -> Addr {
        let hints = self
            .inner
            .bound_sockets()
            .into_iter()
            .map(loopback_for_unspecified)
            .collect();
        Addr {
            node: self.node_id(),
            hints,
        }
    }

    /// iroh's own bound-socket set, unrewritten: the endpoint binds a v4 socket and, where the host
    /// has one, a v6 socket, each reported at the address it was actually bound to.
    fn bound_sockets(&self) -> Vec<SocketAddr> {
        self.inner.bound_sockets()
    }

    async fn connect(&self, addr: Addr) -> Result<IrohSession, Error> {
        let endpoint_addr = to_endpoint_addr(addr).map_err(|err| Error::Connect(Box::new(err)))?;
        let conn = self
            .inner
            .connect(endpoint_addr, ALPN)
            .await
            .map_err(|err| Error::Connect(Box::new(err)))?;
        // Cannot fail in practice: iroh's TLS proves the remote holds the dialled id, which is a `NodeId`
        // that already passed the parse. Kept so `peer` is stored the same way on both sides; the accept
        // side below is the live refusal.
        let peer = peer_of(conn.remote_id()).map_err(|err| refuse(&conn, err, Error::Connect))?;
        Ok(IrohSession { conn, peer })
    }

    /// The feed is read as the bind allows ([`Finding::seed`]): a bind that finds peers by key
    /// never waits on it, and a hints-only bind waits for its first answer.
    async fn connect_with_updates(
        &self,
        addr: Addr,
        updates: HintStream,
    ) -> Result<IrohSession, Error> {
        self.connect(self.finding.seed(addr, updates).await?).await
    }

    async fn accept(&self) -> Result<IrohSession, Error> {
        let incoming = self.inner.accept().await.ok_or(Error::Closed)?;
        let conn = incoming.await.map_err(|err| Error::Accept(Box::new(err)))?;
        let peer = peer_of(conn.remote_id()).map_err(|err| refuse(&conn, err, Error::Accept))?;
        Ok(IrohSession { conn, peer })
    }

    async fn close(&self) {
        self.inner.close().await;
    }
}

/// An iroh session: a single authenticated, encrypted connection.
pub struct IrohSession {
    conn: Connection,
    /// The peer's identity, parsed once where the session is built: `peer` is synchronous and cannot
    /// refuse, so a key that is not a usable identity never becomes a session at all.
    peer: NodeId,
}

impl Session for IrohSession {
    type Security = Sealed;
    type Write = SendStream;
    type Read = RecvStream;

    fn peer(&self) -> NodeId {
        self.peer
    }

    async fn open_bi(&self) -> Result<(SendStream, RecvStream), Error> {
        self.conn
            .open_bi()
            .await
            .map_err(|err| Error::Stream(Box::new(err)))
    }

    async fn accept_bi(&self) -> Result<(SendStream, RecvStream), Error> {
        self.conn
            .accept_bi()
            .await
            .map_err(|err| Error::Stream(Box::new(err)))
    }

    async fn wait_closed(&self) {
        self.conn.closed().await;
    }

    /// A QUIC connection stays open while any of its streams is held, so dropping the session alone can
    /// leave it carrying streams a detached task still owns. Closing it ends every one of them at once.
    fn close(&self) {
        self.conn.close(0u32.into(), b"closed");
    }

    /// The path iroh has selected for application data, reduced to a [`ConnInfo`]. iroh holds every
    /// open path and marks one as selected; a hole-punched session keeps its relay path open as a
    /// standby beside the direct one, so only the selected path says where the bytes go.
    fn conn_info(&self) -> ConnInfo {
        conn_info(&self.conn.paths())
    }

    /// iroh's path events, read down to the [`Path`] each newly selected path names.
    ///
    /// Subscribed before the current path is read, as iroh's path watcher asks, so a change between
    /// the read and the first poll is still seen.
    fn path_changes(&self) -> PathChanges {
        let events = self.conn.path_events();
        PathChanges::new(Selections {
            events,
            said: conn_info(&self.conn.paths()).path,
            conn: self.conn.weak_handle(),
        })
    }
}

/// Reduce iroh's open-path snapshot to a [`ConnInfo`] for the selected path, the one carrying bytes.
/// The other open paths are standbys and say nothing about where bytes go. No path selected yet (or
/// the selected one just closed) is [`Path::Unknown`] with no rtt or remote, never a guess from
/// whichever path happens to be open.
fn conn_info(paths: &PathList<'_>) -> ConnInfo {
    selected(paths.iter())
}

/// The [`ConnInfo`] of the one selected path among `paths`, over [`OpenPath`] so a test can hand it
/// a path set iroh would only build on a live connection.
fn selected<P: OpenPath>(paths: impl IntoIterator<Item = P>) -> ConnInfo {
    let Some(carrying) = paths.into_iter().find(OpenPath::is_selected) else {
        return ConnInfo::default();
    };
    let remote = carrying.remote_addr();
    ConnInfo {
        path: path_of(remote),
        rtt: Some(carrying.rtt()),
        remote: direct_addr(remote),
    }
}

/// What the reduction reads of one open path. iroh's own path type is built only inside a live
/// connection, so this is the seam the selection test stands a fake path set on.
trait OpenPath {
    /// Whether iroh has selected this path to carry application data.
    fn is_selected(&self) -> bool;
    /// Where the path goes: an IP address, a relay, or a custom transport.
    fn remote_addr(&self) -> &TransportAddr;
    /// The path's own round-trip estimate.
    fn rtt(&self) -> Duration;
}

impl OpenPath for iroh::endpoint::Path<'_> {
    fn is_selected(&self) -> bool {
        iroh::endpoint::Path::is_selected(self)
    }

    fn remote_addr(&self) -> &TransportAddr {
        iroh::endpoint::Path::remote_addr(self)
    }

    fn rtt(&self) -> Duration {
        iroh::endpoint::Path::rtt(self)
    }
}

/// The [`Path`] a path's remote address names. A relay path keeps its relay's URL. A custom
/// transport's address (or any later variant of iroh's `non_exhaustive` address) is not a kind this
/// crate can name yet, so it is [`Path::Unknown`] rather than a guess.
fn path_of(addr: &TransportAddr) -> Path {
    match addr {
        TransportAddr::Ip(_) => Path::Direct,
        TransportAddr::Relay(relay) => Path::Relayed(Relay::from(Url::clone(relay))),
        _ => Path::Unknown,
    }
}

/// The direct socket address of a path, if it is an IP path. A relay path (or any future non-IP path
/// variant of iroh's `non_exhaustive` address) has no direct socket address to report, so it yields
/// `None` and [`ConnInfo::remote`] stays absent.
fn direct_addr(addr: &TransportAddr) -> Option<SocketAddr> {
    match addr {
        TransportAddr::Ip(socket) => Some(*socket),
        _ => None,
    }
}

/// The stream behind [`IrohSession::path_changes`]: iroh's path events, kept to the selections that
/// move the bytes to a different [`Path`].
///
/// iroh selects a new path id when, say, the direct path moves from IPv4 to IPv6; both are
/// [`Path::Direct`], so the change is not said twice. The connection is held weakly: a reader holding
/// this stream must not keep a closed session's connection alive.
struct Selections {
    events: PathEventStream,
    /// The path last said, or read when the stream was made, so only a different one is said next.
    said: Path,
    conn: WeakConnectionHandle,
}

impl Stream for Selections {
    type Item = Path;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Path>> {
        let this = self.get_mut();
        loop {
            let selected = match ready!(Pin::new(&mut this.events).poll_next(cx)) {
                None => return Poll::Ready(None),
                Some(PathEvent::Selected { remote_addr, .. }) => path_of(&remote_addr),
                // A selection may be among the dropped events, so answer with the path in force now.
                // A connection that will not upgrade has closed, and so has this stream.
                Some(PathEvent::Lagged { .. }) => {
                    let Some(conn) = this.conn.upgrade() else {
                        return Poll::Ready(None);
                    };
                    conn_info(&conn.paths()).path
                }
                // Opening and closing a path moves no bytes; only a selection does.
                Some(_) => continue,
            };
            if selected != this.said {
                this.said = selected.clone();
                return Poll::Ready(Some(selected));
            }
        }
    }
}

/// Rewrite an unspecified bind address (`0.0.0.0` / `[::]`) to loopback so it is directly dialable
/// locally and never handed out as a wildcard hint.
fn loopback_for_unspecified(socket: SocketAddr) -> SocketAddr {
    match socket.ip() {
        IpAddr::V4(v4) if v4.is_unspecified() => {
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), socket.port())
        }
        IpAddr::V6(v6) if v6.is_unspecified() => {
            SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), socket.port())
        }
        _ => socket,
    }
}

/// The [`NodeId`] an iroh endpoint id names, or why it names none.
///
/// iroh's key parse only decompresses, and its TLS check is `verify_strict`, which a torsioned twin
/// passes for the holder of the untwisted secret. So the id a handshake proved is parsed again here,
/// and a twin is refused rather than attributed.
fn peer_of(id: EndpointId) -> Result<NodeId, KeyError> {
    NodeId::try_new(CryptoKind::Ed25519, *id.as_bytes())
}

/// Close a connection whose peer key did not parse and classify the refusal as `class` (a dial or an
/// accept failure), with the [`KeyError`] as its source. The close is explicit, the same one
/// [`Session::close`] sends, so the peer learns now rather than when the last handle drops.
fn refuse(conn: &Connection, err: KeyError, class: fn(BoxError) -> Error) -> Error {
    conn.close(0u32.into(), b"closed");
    class(Box::new(err))
}

fn to_endpoint_addr(addr: Addr) -> Result<EndpointAddr, iroh::KeyParsingError> {
    let id = PublicKey::from_bytes(addr.node.key())?;
    let mut endpoint_addr = EndpointAddr::new(id);
    for hint in addr.hints {
        endpoint_addr = endpoint_addr.with_ip_addr(hint);
    }
    Ok(endpoint_addr)
}

/// Binding the local endpoint failed.
#[derive(Debug, thiserror::Error)]
pub enum BindError {
    /// The underlying iroh endpoint failed to bind (port in use, socket error).
    #[error("bind iroh endpoint")]
    Bind(#[from] iroh::endpoint::BindError),
    /// The requested fixed bind address was not a valid socket address.
    #[error("invalid bind address")]
    Addr(#[from] iroh::endpoint::InvalidSocketAddr),
}

/// A reach change on a bound endpoint failed. The reach read back by [`Endpoint::reach`] is unchanged.
#[derive(Debug, thiserror::Error)]
pub enum SetReachError {
    /// The endpoint was bound local or offline, with no relay and no resolver to change.
    #[error("a local or offline endpoint has no relay or resolver to change")]
    Local,
    /// The endpoint is closed.
    #[error("the endpoint is closed")]
    Closed,
    /// The new resolver's lookup services could not start on the endpoint.
    #[error("start the lookups for the new resolver")]
    Lookup(#[source] AddressLookupBuilderError),
}

#[cfg(test)]
mod lib_tests;
#[cfg(test)]
mod reach_tests;
