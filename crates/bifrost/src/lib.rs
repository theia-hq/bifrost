//! Bifrost: the pubkey-addressed overlay substrate.
//!
//! This umbrella is what applications depend on. It re-exports the transport + discovery interface and the
//! wire, so an app speaks only `bifrost::` and names a concrete transport exactly once, at its
//! composition root, for example:
//!
//! ```ignore
//! let node = bifrost::Node::new(bifrost_iroh::Endpoint::bind().await?, bifrost::NoDiscovery);
//! ```
//!
//! After that line, nothing in the app refers to iroh: it dials `bifrost::NodeId`s and moves bytes
//! with `bifrost::wire`, over whatever transport was composed in.

pub use bifrost_transport::{
    Addr, ConnInfo, Discovery, Error, NoDiscovery, Node, NodeId, Path, Session, StaticDiscovery,
    Transport,
};
