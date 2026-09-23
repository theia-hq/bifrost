//! The effective user id, for the key file's owner check.
//!
//! The one `unsafe` in this crate, allowed back on this one function and nowhere else. The standard library has no
//! call for the effective uid, and the owner check means nothing without it: a node running as root
//! must refuse a key file some other user placed at its path.

/// This process's effective user id.
#[allow(unsafe_code)]
pub(crate) fn effective() -> u32 {
    // SAFETY: `geteuid` takes no arguments, reads only the calling process's credentials, touches no
    // memory of ours, and cannot fail (POSIX: "shall always be successful").
    unsafe { libc::geteuid() }
}
