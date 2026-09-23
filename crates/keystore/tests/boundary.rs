//! The storage core's boundary, pinned: what it depends on, where it is not re-exported, what it
//! never names, and that nothing public hands out a bare seed.
//!
//! These read the crate's own manifest and sources. They are tripwires rather than proofs: a scan can
//! be evaded on purpose. What they catch is the drift that arrives one reasonable-looking line at a
//! time, which is how a storage crate grows a posture.

use std::fs;
use std::path::{Path, PathBuf};

fn crate_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// The keys of one `[section]` of a manifest.
#[allow(clippy::expect_used)]
fn manifest_keys(manifest: &Path, section: &str) -> Vec<String> {
    let text = fs::read_to_string(manifest).expect("the manifest is readable");
    let mut keys = Vec::new();
    let mut inside = false;
    for line in text.lines().map(str::trim) {
        if line.starts_with('[') {
            inside = line == section;
            continue;
        }
        if !inside || line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(key) = line.split(['=', '.']).next() {
            keys.push(key.trim().to_owned());
        }
    }
    keys.sort();
    keys
}

/// The shipped source files: everything under `src/` except the tests and their helpers.
#[allow(clippy::expect_used)]
fn shipped_sources() -> Vec<(String, String)> {
    let mut sources = Vec::new();
    for entry in fs::read_dir(crate_dir().join("src")).expect("src/ is readable") {
        let path = entry.expect("src/ lists").path();
        let name = path
            .file_name()
            .map(|name| name.to_string_lossy().into_owned());
        let Some(name) = name else { continue };
        if name.ends_with("_tests.rs") || name == "test_dir.rs" {
            continue;
        }
        sources.push((
            name,
            fs::read_to_string(&path).expect("a source is readable"),
        ));
    }
    assert!(
        sources.len() >= 7,
        "the scan found too few sources to mean anything"
    );
    sources
}

/// Source text with every `//` comment removed, so the docs may explain what the code must not do.
fn code_only(source: &str) -> String {
    source
        .lines()
        .map(|line| line.find("//").map_or(line, |at| &line[..at]))
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn the_storage_core_depends_on_the_node_identity_and_crypto_only() {
    assert_eq!(
        manifest_keys(&crate_dir().join("Cargo.toml"), "[dependencies]"),
        [
            "argon2",
            "bifrost-core",
            "chacha20poly1305",
            "getrandom",
            "icu_normalizer",
            "thiserror",
            "zeroize"
        ]
    );
    // `libc` for the effective uid the owner check compares against, and nothing else.
    assert_eq!(
        manifest_keys(
            &crate_dir().join("Cargo.toml"),
            "[target.'cfg(unix)'.dependencies]"
        ),
        ["libc"]
    );
}

#[test]
fn the_facade_does_not_carry_the_keystore() {
    let facade = crate_dir().join("../bifrost/Cargo.toml");
    let dependencies = manifest_keys(&facade, "[dependencies]");
    assert!(
        dependencies.iter().any(|key| key == "bifrost-core"),
        "{} is not the facade manifest this test means to read",
        facade.display()
    );
    assert!(!dependencies.iter().any(|key| key == "keystore"));
}

#[test]
fn the_storage_code_never_names_posture_home_prompting_or_signing() {
    // The words of the concerns that belong to the caller: where a key lives and whether one is made
    // (home, posture, intent, mint, ephemeral), how a person is asked (prompt, tty, stdin, env), and
    // what the key is for (any signing surface). A storage core that needs one of these is growing a
    // concern it must not own.
    const FORBIDDEN: &[&str] = &[
        "Home",
        "home",
        "HOME",
        "home_dir",
        "Posture",
        "posture",
        "Intent",
        "intent",
        "mint",
        "Mint",
        "ephemeral",
        "Ephemeral",
        "Prompt",
        "prompt",
        "tty",
        "stdin",
        "env",
        "var_os",
        "sign",
        "sign_document",
        "Signer",
        "Signature",
        "SigningKey",
    ];
    for (name, source) in shipped_sources() {
        let code = code_only(&source);
        for token in code.split(|c: char| !(c.is_alphanumeric() || c == '_')) {
            assert!(
                !FORBIDDEN.contains(&token),
                "{name} names `{token}`, a concern the storage core must not own"
            );
        }
    }
}

#[test]
fn no_public_function_hands_out_a_bare_seed() {
    for (name, source) in shipped_sources() {
        let code = code_only(&source);
        let mut signature = String::new();
        for line in code.lines().map(str::trim) {
            let public = line.starts_with("pub fn ") || line.starts_with("pub const fn ");
            if signature.is_empty() && !public {
                continue;
            }
            signature.push_str(line);
            signature.push(' ');
            if !(line.contains('{') || line.ends_with(';')) {
                continue;
            }
            if let Some((_, returns)) = signature.split_once("->") {
                let returns = returns.split('{').next().unwrap().trim();
                assert!(
                    !returns.contains("[u8")
                        || returns.starts_with('&')
                        || returns.contains("Zeroizing<"),
                    "{name}: `{}` returns key-sized bytes by value, outside a wiping owner",
                    signature.trim()
                );
            }
            signature.clear();
        }
    }
    // Nor may a trait do it: the only impls a `Secret` carries are the ones that cannot move bytes out.
    let secret = code_only(&fs::read_to_string(crate_dir().join("src/secret.rs")).unwrap());
    let lines: Vec<&str> = secret
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect();
    for line in &lines {
        if line.starts_with("impl") && line.contains(" for Secret") {
            assert!(
                [
                    "impl Drop for Secret",
                    "impl ZeroizeOnDrop for Secret",
                    "impl fmt::Debug for Secret"
                ]
                .iter()
                .any(|allowed| line.starts_with(allowed)),
                "secret.rs: `{line}` is an impl that could hand the seed out"
            );
        }
    }
    let declared = lines
        .iter()
        .position(|line| line.starts_with("pub struct Secret"))
        .unwrap();
    assert!(
        !lines[declared - 1].starts_with("#[derive"),
        "secret.rs: `Secret` must derive nothing"
    );
    // A private field, so nothing outside the module reaches the box.
    assert!(
        lines[declared].starts_with("pub struct Secret(Box<"),
        "secret.rs: `Secret`'s field must stay private, found `{}`",
        lines[declared]
    );
    // And no other file may add an impl that takes a `Secret` apart: a conversion or a trait can be
    // written anywhere in the crate, not only beside the type.
    for (name, source) in shipped_sources() {
        if name == "secret.rs" {
            continue;
        }
        for line in code_only(&source).lines().map(str::trim) {
            let opens_secret = line.contains(" for Secret")
                || line.contains("Secret>")
                || line.contains("<&Secret")
                || line.contains("for &Secret");
            assert!(
                !(line.starts_with("impl") && opens_secret),
                "{name}: `{line}` is an impl on `Secret` outside secret.rs"
            );
        }
    }
}

/// argon2 frees its own work memory unwiped, and the last pass's blocks rebuild the key. The only
/// call this crate makes is the one that takes memory it owns and wipes.
#[test]
fn the_key_derivation_runs_in_memory_this_crate_wipes() {
    let envelope = code_only(&fs::read_to_string(crate_dir().join("src/envelope.rs")).unwrap());
    assert!(envelope.contains(".hash_password_into_with_memory("));
    assert!(!envelope.contains(".hash_password_into("));
    assert!(envelope.contains("let mut blocks = Zeroizing::new(Vec::new());"));
}

/// Wiping on drop cannot be watched from a test: reading freed memory is undefined behaviour, so
/// any test that claimed to see the wipe would be reporting nothing. What CAN be pinned is that the
/// owners are built to wipe: the seed's box has a `Drop` that zeroizes it, and the passphrase lives
/// in a `Zeroizing` buffer.
#[test]
#[allow(clippy::expect_used)]
fn the_seed_and_passphrase_owners_are_built_to_wipe() {
    let read = |name: &str| {
        code_only(&fs::read_to_string(crate_dir().join("src").join(name)).expect("readable"))
    };
    let secret = read("secret.rs");
    let drop = secret
        .split("impl Drop for Secret")
        .nth(1)
        .expect("`Secret` has a `Drop`");
    let body = drop.split("\n}").next().expect("the `Drop` has a body");
    assert!(
        body.contains("self.0.zeroize()"),
        "`Secret`'s `Drop` must zeroize the seed"
    );
    assert!(read("passphrase.rs").contains("pub struct Passphrase(Zeroizing<Vec<u8>>);"));
}
