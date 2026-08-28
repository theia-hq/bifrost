//! Core vocabulary for Bifrost.
//!
//! The self-certifying node identity ([`NodeId`]) and its crypto suite tag ([`CryptoKind`]).
//! Everything here is pure domain: no transport, storage, or codec concerns live in this crate.

mod id;

pub use id::{CryptoKind, NodeId, NodeIdParseError, derive_ed25519_child_secret};

#[cfg(test)]
mod id_tests;
