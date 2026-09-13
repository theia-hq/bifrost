//! The sealed wrapper over a real backend: quirk on loopback UDP.
//!
//! quirk declares `Announced` and moves plaintext bytes on one stream per connection. Wrapping it
//! upgrades the profile and gives consumers logical streams inside its one, with no change to the
//! quirk repository. These cases run the shared conformance suite through that composition.

use bifrost::{Node, NodeId, StaticDiscovery, Transport};
use bifrost_conformance::{close_drains, identity_binding, reach_roundtrip};
use bifrost_noise::Noise;
use bifrost_quirk::Endpoint;

fn seed(byte: u8) -> [u8; NodeId::KEY_LEN] {
    [byte; NodeId::KEY_LEN]
}

// A test helper, not a `#[test]` fn, so `allow-expect-in-tests` does not reach the expects inside it.
#[allow(clippy::expect_used)]
async fn sealed(byte: u8) -> Noise<Endpoint> {
    let inner = Endpoint::bind_with_secret(seed(byte))
        .await
        .expect("bind quirk");
    Noise::new(inner, seed(byte)).expect("wrap quirk")
}

/// A wrapped-quirk session carries the same blob round-trip as any other transport.
#[tokio::test]
async fn wrapped_quirk_reach_roundtrip() {
    let receiver = sealed(31).await;
    let mut discovery = StaticDiscovery::new();
    discovery.insert(receiver.node_id(), receiver.local_addr().hints);
    let sender = Node::new(sealed(32).await, discovery);
    reach_roundtrip(sender, receiver).await;
}

/// A wrapped-quirk sender that writes, finishes, and closes still delivers every byte.
#[tokio::test]
async fn wrapped_quirk_close_drains() {
    let receiver = sealed(33).await;
    let mut discovery = StaticDiscovery::new();
    discovery.insert(receiver.node_id(), receiver.local_addr().hints);
    let sender = Node::new(sealed(34).await, discovery);
    close_drains(sender, receiver).await;
}

/// Both ends attribute the identity the wrapper handshake proved over the plaintext inner.
#[tokio::test]
async fn wrapped_quirk_identity_binding() {
    identity_binding(sealed(35).await, sealed(36).await).await;
}
