//! Core vocabulary for Bifrost.
//!
//! The transport-neutral atoms every layer speaks: the self-certifying node identity ([`NodeId`]) and
//! its crypto suite tag ([`CryptoKind`]); how to reach a peer ([`Addr`]); why a reach failed
//! ([`Error`]); how a session travels ([`Path`]/[`ConnInfo`]); and the [`Discovery`] contract that
//! resolves an identity to address hints. Everything here is async-free vocabulary: no tokio, no
//! byte-moving contract, no storage or codec concerns. The one thing that genuinely needs async IO,
//! the `Transport` + `Session` seam, lives in `bifrost-transport`.

mod addr;
mod conn;
mod discovery;
mod error;
mod id;

pub use addr::Addr;
pub use conn::{ConnInfo, Path};
pub use discovery::{Discovery, Layered, NoDiscovery, StaticDiscovery};
pub use error::{BoxError, Error};
pub use id::{CryptoKind, NodeId, NodeIdParseError, derive_ed25519_child_secret};

#[cfg(test)]
mod id_tests;
