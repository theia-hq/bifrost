//! Bifrost: the pubkey-addressed overlay substrate.
//!
//! This umbrella is what applications depend on. It owns [`Node`], the composition root an app holds,
//! and re-exports the transport + discovery interface and the [`wire`], so an app speaks only
//! `bifrost::` and names a concrete transport exactly once, at its composition root, for example:
//!
//! ```ignore
//! let node = bifrost::Node::new(bifrost_iroh::Endpoint::bind().await?, bifrost::NoDiscovery);
//! ```
//!
//! After that line, nothing in the app refers to iroh: it dials `bifrost::NodeId`s and moves bytes
//! with `bifrost::wire`, over whatever transport was composed in.

mod node;

pub use bifrost_core::{
    Addr, ConnInfo, CryptoKind, Discovery, Error, Layered, NoDiscovery, NodeId, NodeIdParseError,
    Path, StaticDiscovery,
};
pub use bifrost_transport::{Session, Transport};
pub use bifrost_wire as wire;
pub use node::Node;
