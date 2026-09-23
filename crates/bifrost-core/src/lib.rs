//! Core vocabulary for Bifrost.
//!
//! The transport-neutral atoms every layer speaks: the self-certifying node identity ([`NodeId`]) and
//! its crypto suite tag ([`CryptoKind`]); how to reach a peer ([`Addr`]); why a reach failed
//! ([`Error`]); how a session travels ([`Path`]/[`ConnInfo`]); and the [`Discovery`] contract that
//! feeds a dial address hints for an identity ([`HintStream`] of [`AddrUpdate`]). Everything here is
//! runtime-free vocabulary: no tokio, no byte-moving contract, no storage or codec concerns. A hint
//! feed is a [`Stream`](futures_core::Stream) the caller's executor drives, never a task this crate
//! starts. The one thing that genuinely needs async IO, the `Transport` + `Session` interface, lives
//! in `bifrost-transport`.

mod addr;
mod conn;
mod discovery;
mod error;
mod hints;
mod id;
mod refusal;

pub use addr::Addr;
pub use conn::{ConnInfo, Path};
pub use discovery::{Discovery, Layered, NoDiscovery, StaticDiscovery};
pub use error::{BoxError, Error};
pub use hints::{AddrUpdate, HintStream, Latest};
pub use id::{CryptoKind, NodeId, NodeIdParseError, derive_ed25519_child_secret};
pub use refusal::{Refusal, RefusalDetail, RefusalDetailError};

#[cfg(test)]
mod discovery_tests;
#[cfg(test)]
mod id_tests;
