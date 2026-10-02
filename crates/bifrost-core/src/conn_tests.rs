//! The path vocabulary: how large a path is to hold, and what a fixed path stream says.

use core::pin::Pin;
use core::task::{Context, Poll, Waker};

use futures_core::Stream;
use url::Url;

use crate::{Path, PathChanges, Relay};

/// A path stays two words, the boxed relay and the variant's tag. It travels inside every snapshot
/// and stream item a consumer holds, where an inline `Url` would make it many times larger, so this
/// pins the box against a well-meaning unboxing.
#[test]
fn a_path_is_two_words() {
    assert_eq!(size_of::<Path>(), 2 * size_of::<usize>());
}

/// A relay reads back the URL it was made from, and prints as it.
#[test]
fn a_relay_reads_back_its_url() {
    let url = Url::parse("https://relay.example").expect("a url");
    let relay = Relay::from(url.clone());
    assert_eq!(relay.url(), &url);
    assert_eq!(relay.to_string(), "https://relay.example/");
}

/// A fixed stream says its one path, then ends.
#[test]
fn a_fixed_path_is_said_once_then_ends() {
    let mut changes = PathChanges::fixed(Path::Direct);
    assert_eq!(poll(&mut changes), Poll::Ready(Some(Path::Direct)));
    assert_eq!(poll(&mut changes), Poll::Ready(None));
}

/// One poll with a no-op waker: a fixed stream never waits.
fn poll(changes: &mut PathChanges) -> Poll<Option<Path>> {
    Pin::new(changes).poll_next(&mut Context::from_waker(Waker::noop()))
}
