use std::fs;

use zeroize::Zeroizing;

use super::{KeyFile, lacks_hard_links};
use crate::envelope::{AT_PUBLIC, Envelope, HEADER_LEN, SEALED_LEN};
use crate::error::{Error, FormatError};
use crate::kind::Kind;
use crate::method::{Method, Protection};
use crate::passphrase::Passphrase;
use crate::secret::Secret;
use crate::stored::Stored;
use crate::test_dir::TestDir;

fn passphrase(text: &str) -> Passphrase {
    Passphrase::new(Zeroizing::new(text.as_bytes().to_vec())).unwrap()
}

fn key_file(dir: &TestDir) -> KeyFile {
    KeyFile::device(dir.join("identity.key"))
}

fn plain_file(dir: &TestDir, seed: [u8; 32]) -> (KeyFile, Secret) {
    let file = key_file(dir);
    let secret = Secret::copy_of(&seed);
    file.write(&secret, Protection::Plain).unwrap();
    (file, secret)
}

fn sealed_file(dir: &TestDir, seed: [u8; 32], under: &Passphrase) -> (KeyFile, Secret) {
    let file = key_file(dir);
    let secret = Secret::copy_of(&seed);
    file.write(&secret, Protection::Passphrase(under)).unwrap();
    (file, secret)
}

/// Put `content` at the key path the way a key file sits, owner-only, so the test reaches the check
/// it is about rather than the mode guard.
fn plant(file: &KeyFile, content: &[u8]) {
    fs::write(file.path(), content).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;

        fs::set_permissions(file.path(), fs::Permissions::from_mode(0o600)).unwrap();
    }
}

fn bytes(file: &KeyFile) -> Vec<u8> {
    fs::read(file.path()).unwrap()
}

fn locked(file: &KeyFile) -> crate::stored::Locked {
    match file.load().unwrap() {
        Some(Stored::Locked(locked)) => locked,
        other => panic!("expected a locked file, found {other:?}"),
    }
}

fn plain(file: &KeyFile) -> Secret {
    match file.load().unwrap() {
        Some(Stored::Plain(secret)) => secret,
        other => panic!("expected a plain file, found {other:?}"),
    }
}

#[test]
fn nothing_at_the_path_loads_as_none() {
    let dir = TestDir::new();
    assert!(key_file(&dir).load().unwrap().is_none());
}

#[test]
fn a_plain_write_reads_back_as_the_same_key() {
    let dir = TestDir::new();
    let (file, secret) = plain_file(&dir, [1; 32]);
    assert_eq!(bytes(&file), [1; 32]);
    let stored = file.load().unwrap().unwrap();
    assert_eq!(stored.method(), Method::Plain);
    assert_eq!(stored.node_id(), secret.node_id());
    assert_eq!(dir.names(), ["identity.key"]);
}

#[test]
fn a_sealed_write_names_its_node_locked_and_opens_to_the_same_key() {
    let dir = TestDir::new();
    let under = passphrase("correct horse battery staple");
    let (file, secret) = sealed_file(&dir, [2; 32], &under);
    assert_eq!(bytes(&file).len(), SEALED_LEN);
    let locked = locked(&file);
    assert_eq!(locked.method(), Method::Passphrase);
    assert_eq!(locked.node_id(), secret.node_id());
    assert_eq!(locked.unlock(&under).unwrap().node_id(), secret.node_id());
    assert_eq!(dir.names(), ["identity.key"]);
}

#[test]
fn a_sealed_file_opens_with_the_keystore_signature() {
    let dir = TestDir::new();
    let (file, _) = sealed_file(&dir, [4; 32], &passphrase("correct horse"));
    assert_eq!(&bytes(&file)[..8], b"KEYSTORE");
}

#[cfg(unix)]
#[test]
fn a_written_key_is_owner_only() {
    use std::os::unix::fs::PermissionsExt as _;

    let dir = TestDir::new();
    let (file, _) = plain_file(&dir, [1; 32]);
    let mode = fs::metadata(file.path()).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o600);
}

#[test]
fn a_write_never_lands_over_an_existing_file() {
    let dir = TestDir::new();
    let (file, secret) = plain_file(&dir, [1; 32]);
    let before = bytes(&file);
    // Not even the same key, and not under another method.
    for protection in [Protection::Plain, Protection::Passphrase(&passphrase("x"))] {
        assert!(matches!(
            file.write(&secret, protection),
            Err(Error::Occupied { .. })
        ));
        assert_eq!(bytes(&file), before);
    }
    assert_eq!(dir.names(), ["identity.key"]);
}

#[test]
fn a_wrong_passphrase_and_a_damaged_file_read_the_same() {
    let dir = TestDir::new();
    let under = passphrase("correct horse battery staple");
    let (file, _) = sealed_file(&dir, [2; 32], &under);
    let original = bytes(&file);

    let wrong = locked(&file).unlock(&passphrase("wrong")).unwrap_err();
    assert_eq!(bytes(&file), original);

    let mut damaged = original.clone();
    damaged[SEALED_LEN - 1] ^= 0x01;
    plant(&file, &damaged);
    let corrupt = locked(&file).unlock(&under).unwrap_err();

    assert!(matches!(wrong, Error::Unlock { .. }));
    assert!(matches!(corrupt, Error::Unlock { .. }));
    assert_eq!(wrong.to_string(), corrupt.to_string());
}

#[test]
fn a_malformed_file_is_refused_by_name_and_left_alone() {
    let dir = TestDir::new();
    let file = key_file(&dir);
    for (content, expected) in [
        (vec![1; 31], FormatError::Size { found: 31 }),
        (vec![1; 33], FormatError::Size { found: 33 }),
        // A version 1 sealed file cut to the plain length: refused as sealed, never read as a seed.
        (
            [&b"KEYSTORE"[..], &[1; 24]].concat(),
            FormatError::SealedSize { found: 32 },
        ),
    ] {
        plant(&file, &content);
        match file.load() {
            Err(Error::Format { source, .. }) => assert_eq!(source, expected),
            other => panic!("expected a format refusal, got {other:?}"),
        }
        assert_eq!(bytes(&file), content);
    }
}

#[test]
fn a_file_past_the_read_cap_is_refused_on_its_size_without_being_read() {
    let dir = TestDir::new();
    let file = key_file(&dir);
    // It opens with a version 1 signature, so had it been read the parser would call it a damaged
    // sealed file; a plain size refusal is what shows it was judged on its length alone. Modest on
    // purpose: if the cap regresses, this test must fail, not make the loader read gigabytes.
    let content = [&b"KEYSTORE"[..], &[1], &vec![0; 64 * 1024]].concat();
    plant(&file, &content);
    match file.load() {
        Err(Error::Format { source, .. }) => {
            assert_eq!(
                source,
                FormatError::Size {
                    found: content.len() as u64
                }
            );
        }
        other => panic!("expected a size refusal, got {other:?}"),
    }
}

#[cfg(unix)]
#[test]
fn a_file_group_or_other_can_read_is_refused() {
    use std::os::unix::fs::PermissionsExt as _;

    let dir = TestDir::new();
    let (file, _) = plain_file(&dir, [1; 32]);
    for mode in [0o640, 0o604, 0o660] {
        fs::set_permissions(file.path(), fs::Permissions::from_mode(mode)).unwrap();
        assert!(matches!(
            file.load(),
            Err(Error::Permissive { mode: found, .. }) if found == mode
        ));
    }
}

#[cfg(unix)]
#[test]
fn a_file_owned_by_another_user_is_refused_and_one_owned_by_root_is_not() {
    use std::os::unix::fs::MetadataExt as _;

    let dir = TestDir::new();
    let (file, _) = plain_file(&dir, [1; 32]);
    if fs::metadata(file.path()).unwrap().uid() == 0 {
        // Run as root, every file here is root's, which the check allows: give this one to uid 1.
        std::os::unix::fs::chown(file.path(), Some(1), None).unwrap();
    }
    let metadata = fs::metadata(file.path()).unwrap();
    let owner = metadata.uid();
    // The same owner-only file, judged as if this process ran as someone else.
    let stranger = owner.wrapping_add(1).max(1);
    assert!(file.guard_access(&metadata, owner).is_ok());
    match file.guard_access(&metadata, stranger) {
        Err(Error::Owner { owner: found, .. }) => assert_eq!(found, owner),
        other => panic!("expected an owner refusal, got {other:?}"),
    }
    // A file root owns is accepted by whoever loads it; `/` is one every unix has.
    let root_owned = fs::metadata("/").unwrap();
    assert_eq!(root_owned.uid(), 0);
    assert!(!matches!(
        file.guard_access(&root_owned, stranger),
        Err(Error::Owner { .. })
    ));
}

#[test]
fn a_directory_at_the_path_is_not_a_key_file() {
    let dir = TestDir::new();
    let file = key_file(&dir);
    fs::create_dir(file.path()).unwrap();
    assert!(matches!(file.load(), Err(Error::NotAFile { .. })));
}

#[cfg(unix)]
#[test]
fn a_pipe_at_the_path_is_refused_without_blocking() {
    use core::time::Duration;
    use std::sync::mpsc;

    let dir = TestDir::new();
    let file = key_file(&dir);
    let made = std::process::Command::new("mkfifo")
        .arg(file.path())
        .status()
        .unwrap();
    assert!(made.success());
    // On a thread with a deadline: a loader that opens the pipe blocks until a writer appears, and
    // this test must fail rather than hang when that happens.
    let (done, outcome) = mpsc::channel();
    std::thread::spawn(move || {
        let refused = matches!(file.load(), Err(Error::NotAFile { .. }));
        let _ = done.send(refused);
    });
    match outcome.recv_timeout(Duration::from_secs(10)) {
        Ok(refused) => assert!(
            refused,
            "a pipe at the key path was not refused as not a file"
        ),
        Err(_) => panic!("the load blocked on a pipe at the key path instead of refusing it"),
    }
}

#[test]
fn adopting_the_key_already_held_changes_nothing() {
    let dir = TestDir::new();
    let (file, secret) = plain_file(&dir, [2; 32]);
    let under = passphrase("correct horse battery staple");
    // Offered sealed, the plain file stays plain: adopting never changes a method.
    file.adopt(&secret, Protection::Passphrase(&under)).unwrap();
    assert_eq!(bytes(&file), [2; 32]);
}

#[test]
fn adopting_over_a_sealed_file_proves_its_claim_by_unlocking_it() {
    let dir = TestDir::new();
    let under = passphrase("correct horse battery staple");
    let (file, secret) = sealed_file(&dir, [2; 32], &under);
    let before = bytes(&file);
    file.adopt(&secret, Protection::Passphrase(&under)).unwrap();
    // With no passphrase, the header's claim is all there is, and a claim is not enough.
    match file.adopt(&secret, Protection::Plain) {
        Err(Error::Unconfirmed { claimed, .. }) => assert_eq!(claimed, secret.node_id()),
        other => panic!("expected the claim to go unconfirmed, got {other:?}"),
    }
    assert_eq!(bytes(&file), before);
}

#[test]
fn a_sealed_file_claiming_the_adopted_key_is_not_taken_at_its_word() {
    let dir = TestDir::new();
    let under = passphrase("correct horse battery staple");
    let (file, _) = sealed_file(&dir, [2; 32], &under);
    // Rewrite the header to claim another node: the file loads as that node, and seals a key that
    // is not it.
    let claimed = Secret::copy_of(&[3; 32]);
    let mut forged = bytes(&file);
    forged[AT_PUBLIC..HEADER_LEN].copy_from_slice(claimed.node_id().key());
    plant(&file, &forged);
    assert_eq!(locked(&file).node_id(), claimed.node_id());

    assert!(matches!(
        file.adopt(&claimed, Protection::Passphrase(&under)),
        Err(Error::Unlock { .. })
    ));
    assert!(matches!(
        file.adopt(&claimed, Protection::Plain),
        Err(Error::Unconfirmed { .. })
    ));
    assert_eq!(bytes(&file), forged);
}

#[test]
fn adopting_over_a_different_key_is_refused_and_leaves_it() {
    let dir = TestDir::new();
    let (file, held) = plain_file(&dir, [1; 32]);
    let incoming = Secret::copy_of(&[9; 32]);
    match file.adopt(&incoming, Protection::Plain) {
        Err(Error::Different {
            existing,
            incoming: offered,
            ..
        }) => {
            assert_eq!(existing, held.node_id());
            assert_eq!(offered, incoming.node_id());
        }
        other => panic!("expected a refusal naming both keys, got {other:?}"),
    }
    assert_eq!(bytes(&file), [1; 32]);
}

#[test]
fn adopting_into_absence_writes_the_key() {
    let dir = TestDir::new();
    let file = key_file(&dir);
    let secret = Secret::copy_of(&[4; 32]);
    file.adopt(&secret, Protection::Plain).unwrap();
    assert_eq!(plain(&file).node_id(), secret.node_id());
}

#[test]
fn adopting_over_an_unreadable_file_refuses_rather_than_replacing_it() {
    let dir = TestDir::new();
    let file = key_file(&dir);
    plant(&file, &[1; 31]);
    assert!(matches!(
        file.adopt(&Secret::copy_of(&[4; 32]), Protection::Plain),
        Err(Error::Format { .. })
    ));
    assert_eq!(bytes(&file), [1; 31]);
}

#[test]
fn a_plain_key_migrates_to_a_passphrase_and_back_as_the_same_node() {
    let dir = TestDir::new();
    let under = passphrase("correct horse battery staple");
    let (file, secret) = plain_file(&dir, [6; 32]);

    file.migrate(Protection::Plain, Protection::Passphrase(&under))
        .unwrap();
    let locked = locked(&file);
    assert_eq!(locked.node_id(), secret.node_id());
    assert_eq!(locked.unlock(&under).unwrap().node_id(), secret.node_id());

    file.migrate(Protection::Passphrase(&under), Protection::Plain)
        .unwrap();
    assert_eq!(bytes(&file), [6; 32]);
    assert_eq!(dir.names(), ["identity.key"]);
}

#[test]
fn changing_the_passphrase_reseals_with_a_fresh_salt_and_nonce() {
    let dir = TestDir::new();
    let (old, new) = (passphrase("old"), passphrase("new"));
    let (file, secret) = sealed_file(&dir, [6; 32], &old);
    let before = bytes(&file);

    file.migrate(Protection::Passphrase(&old), Protection::Passphrase(&new))
        .unwrap();
    let after = bytes(&file);
    // Salt, then nonce: neither is reused by a reseal.
    assert_ne!(before[24..40], after[24..40]);
    assert_ne!(before[40..64], after[40..64]);
    assert!(matches!(
        locked(&file).unlock(&old),
        Err(Error::Unlock { .. })
    ));
    assert_eq!(
        locked(&file).unlock(&new).unwrap().node_id(),
        secret.node_id()
    );
}

#[test]
fn a_migration_that_cannot_unlock_leaves_the_file_as_it_was() {
    let dir = TestDir::new();
    let under = passphrase("correct horse battery staple");
    let (file, _) = sealed_file(&dir, [6; 32], &under);
    let before = bytes(&file);

    assert!(matches!(
        file.migrate(
            Protection::Passphrase(&passphrase("wrong")),
            Protection::Plain
        ),
        Err(Error::Unlock { .. })
    ));
    assert!(matches!(
        file.migrate(Protection::Plain, Protection::Passphrase(&under)),
        Err(Error::WrongMethod {
            stored: Method::Passphrase,
            given: Method::Plain,
            ..
        })
    ));
    assert_eq!(bytes(&file), before);
    assert_eq!(dir.names(), ["identity.key"]);
}

#[test]
fn migrating_nothing_is_refused() {
    let dir = TestDir::new();
    assert!(matches!(
        key_file(&dir).migrate(Protection::Plain, Protection::Plain),
        Err(Error::Absent { .. })
    ));
    assert!(dir.names().is_empty());
}

#[test]
fn an_interrupted_migration_leaves_the_original_readable() {
    let dir = TestDir::new();
    let under = passphrase("correct horse battery staple");
    let (file, secret) = plain_file(&dir, [6; 32]);

    // Run the migration up to the rename and stop there, as a crash would: the new form is staged
    // and proven, and the process dies before publishing it. `forget` stands in for the death, so no
    // cleanup runs either.
    let (unlocked, _) = file.unlock(Protection::Plain).unwrap();
    let image = file
        .encode(&unlocked, Protection::Passphrase(&under))
        .unwrap();
    let staged = file.stage(&image).unwrap();
    staged
        .verify(Protection::Passphrase(&under), secret.node_id())
        .unwrap();
    core::mem::forget(staged);

    assert_eq!(bytes(&file), [6; 32]);
    assert_eq!(plain(&file).node_id(), secret.node_id());
    // The orphaned stage is a sibling, and it does not stop the migration from being run again.
    assert_eq!(dir.names().len(), 2);
    file.migrate(Protection::Plain, Protection::Passphrase(&under))
        .unwrap();
    assert_eq!(
        locked(&file).unlock(&under).unwrap().node_id(),
        secret.node_id()
    );
    // And the rerun swept the orphan, which held the key in the form it had before the migration.
    assert_eq!(dir.names(), ["identity.key"]);
}

#[test]
fn a_write_sweeps_only_what_has_the_exact_shape_of_a_stage() {
    let dir = TestDir::new();
    let file = key_file(&dir);
    let orphan = "identity.key.tmp.4242.0123456789abcdef";
    let kept = [
        "identity.key.tmp.notes",
        "identity.key.tmp.4242.0123456789abcde",
        "identity.key.tmp..0123456789abcdef",
        "other.key.tmp.4242.0123456789abcdef",
    ];
    for name in kept.iter().chain([&orphan]) {
        fs::write(dir.join(name), [5; 32]).unwrap();
    }
    file.write(&Secret::copy_of(&[1; 32]), Protection::Plain)
        .unwrap();
    let mut expected = kept.to_vec();
    expected.push("identity.key");
    expected.sort_unstable();
    assert_eq!(dir.names(), expected);
}

#[cfg(unix)]
#[test]
fn the_sweep_leaves_a_link_under_a_stage_name_and_what_it_points_at() {
    let dir = TestDir::new();
    let file = key_file(&dir);
    let precious = dir.join("precious");
    fs::write(&precious, [5; 32]).unwrap();
    let link = dir.join("identity.key.tmp.4242.0123456789abcdef");
    std::os::unix::fs::symlink(&precious, &link).unwrap();
    file.write(&Secret::copy_of(&[1; 32]), Protection::Plain)
        .unwrap();
    assert!(link.symlink_metadata().unwrap().file_type().is_symlink());
    assert_eq!(fs::read(&precious).unwrap(), [5; 32]);
}

#[test]
fn a_migration_never_writes_over_a_file_replaced_since_it_read_it() {
    let dir = TestDir::new();
    let under = passphrase("correct horse battery staple");
    let (file, secret) = plain_file(&dir, [6; 32]);

    // Steps 1 and 2 of a migration, then a restore lands a different key in the window before the
    // rename, the way a second process would.
    let (unlocked, seen) = file.unlock(Protection::Plain).unwrap();
    let image = file
        .encode(&unlocked, Protection::Passphrase(&under))
        .unwrap();
    let restored = dir.join("restored");
    fs::write(&restored, [7; 32]).unwrap();
    fs::rename(&restored, file.path()).unwrap();

    assert!(matches!(
        file.replace(
            &image,
            Protection::Passphrase(&under),
            secret.node_id(),
            &seen
        ),
        Err(Error::Changed { .. })
    ));
    assert_eq!(bytes(&file), [7; 32]);
    assert_eq!(dir.names(), ["identity.key"]);
}

#[test]
fn a_migration_never_writes_over_a_file_changed_in_place_since_it_read_it() {
    let dir = TestDir::new();
    let under = passphrase("correct horse battery staple");
    let (file, secret) = plain_file(&dir, [6; 32]);
    let (unlocked, seen) = file.unlock(Protection::Plain).unwrap();
    let image = file
        .encode(&unlocked, Protection::Passphrase(&under))
        .unwrap();
    // Same file, same length, new contents.
    fs::write(file.path(), [7; 32]).unwrap();

    assert!(matches!(
        file.replace(
            &image,
            Protection::Passphrase(&under),
            secret.node_id(),
            &seen
        ),
        Err(Error::Changed { .. })
    ));
    assert_eq!(bytes(&file), [7; 32]);
}

#[test]
fn a_new_form_that_does_not_read_back_never_replaces_the_original() {
    let dir = TestDir::new();
    let under = passphrase("correct horse battery staple");
    let (file, secret) = plain_file(&dir, [6; 32]);
    let (_, seen) = file.unlock(Protection::Plain).unwrap();

    // A well-formed sealed file, but sealed under a passphrase other than the one the migration is
    // moving to: the stage is written, the test-unlock fails, and the rename must not happen.
    let wrong = Envelope::seal(&secret, Kind::Device, &passphrase("something else")).unwrap();
    assert!(matches!(
        file.replace(
            wrong.image(),
            Protection::Passphrase(&under),
            secret.node_id(),
            &seen
        ),
        Err(Error::Unverified { .. })
    ));
    // And a form that opens, but to another node.
    let other = Secret::copy_of(&[8; 32]);
    let elsewhere = Envelope::seal(&other, Kind::Device, &under).unwrap();
    assert!(matches!(
        file.replace(
            elsewhere.image(),
            Protection::Passphrase(&under),
            secret.node_id(),
            &seen
        ),
        Err(Error::Unverified { .. })
    ));

    assert_eq!(bytes(&file), [6; 32]);
    assert_eq!(dir.names(), ["identity.key"]);
}

#[cfg(unix)]
#[test]
fn a_migration_that_cannot_stage_leaves_the_original_readable() {
    use std::os::unix::fs::PermissionsExt as _;

    let dir = TestDir::new();
    let under = passphrase("correct horse battery staple");
    let (file, secret) = plain_file(&dir, [6; 32]);
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o500)).unwrap();

    let outcome = file.migrate(Protection::Plain, Protection::Passphrase(&under));

    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    assert!(matches!(outcome, Err(Error::Io { .. })));
    assert_eq!(plain(&file).node_id(), secret.node_id());
    assert_eq!(dir.names(), ["identity.key"]);
}

#[cfg(unix)]
#[test]
fn a_migration_through_a_link_rewrites_the_file_the_link_names() {
    let dir = TestDir::new();
    let under = passphrase("correct horse battery staple");
    // The key is kept in a managed directory and linked into place, as a dotfile manager lays it out.
    let kept_dir = dir.join("dotfiles");
    fs::create_dir(&kept_dir).unwrap();
    let kept = KeyFile::device(kept_dir.join("identity.key"));
    let secret = Secret::copy_of(&[6; 32]);
    kept.write(&secret, Protection::Plain).unwrap();
    let file = key_file(&dir);
    std::os::unix::fs::symlink(kept.path(), file.path()).unwrap();

    file.migrate(Protection::Plain, Protection::Passphrase(&under))
        .unwrap();

    // The link is still a link, and the file it names is the sealed one: no plain seed is left
    // anywhere, in either directory.
    assert!(
        file.path()
            .symlink_metadata()
            .unwrap()
            .file_type()
            .is_symlink()
    );
    assert_eq!(bytes(&kept).len(), SEALED_LEN);
    assert_eq!(
        locked(&file).unlock(&under).unwrap().node_id(),
        secret.node_id()
    );
    assert_eq!(dir.names(), ["dotfiles", "identity.key"]);
    assert_eq!(fs::read_dir(&kept_dir).unwrap().count(), 1);
}

#[cfg(unix)]
#[test]
fn a_write_never_lands_through_a_link_even_one_that_points_nowhere() {
    let dir = TestDir::new();
    let file = key_file(&dir);
    let nowhere = dir.join("nowhere.key");
    std::os::unix::fs::symlink(&nowhere, file.path()).unwrap();
    assert!(matches!(
        file.write(&Secret::copy_of(&[1; 32]), Protection::Plain),
        Err(Error::Occupied { .. })
    ));
    assert!(!nowhere.exists());
}

#[test]
fn a_new_key_that_does_not_read_back_is_never_published() {
    let dir = TestDir::new();
    let file = key_file(&dir);
    let under = passphrase("correct horse battery staple");
    let secret = Secret::copy_of(&[6; 32]);
    // Sealed under another passphrase than the one the write is for: the stage is written, its
    // test-unlock fails, and nothing may appear at the path.
    let wrong = Envelope::seal(&secret, Kind::Device, &passphrase("something else")).unwrap();
    assert!(matches!(
        file.create(
            wrong.image(),
            Protection::Passphrase(&under),
            secret.node_id()
        ),
        Err(Error::Unverified { .. })
    ));
    assert!(dir.names().is_empty());
}

fn root_file(dir: &TestDir) -> KeyFile {
    KeyFile::root(dir.join("root.key"))
}

/// The same path, named as the other kind.
fn as_device(file: &KeyFile) -> KeyFile {
    KeyFile::device(file.path())
}

fn wrong_kind(outcome: Result<Option<Stored>, Error>) -> (Kind, Kind) {
    match outcome {
        Err(Error::Format {
            source: FormatError::WrongKind { expected, found },
            ..
        }) => (expected, found),
        other => panic!("expected a refusal by kind, found {other:?}"),
    }
}

#[test]
fn a_root_key_is_written_sealed_as_the_root_kind() {
    let dir = TestDir::new();
    let file = root_file(&dir);
    let under = passphrase("correct horse battery staple");
    let secret = Secret::copy_of(&[4; 32]);
    file.write(&secret, Protection::Passphrase(&under)).unwrap();

    assert_eq!(file.kind(), Kind::Root);
    assert_eq!(bytes(&file).len(), SEALED_LEN);
    assert_eq!(
        locked(&file).unlock(&under).unwrap().node_id(),
        secret.node_id()
    );
    assert_eq!(
        wrong_kind(as_device(&file).load()),
        (Kind::Device, Kind::Root)
    );
}

#[test]
fn a_device_key_file_in_the_root_slot_is_refused_by_kind() {
    let dir = TestDir::new();
    let under = passphrase("correct horse battery staple");
    let (device, secret) = sealed_file(&dir, [4; 32], &under);
    let root = KeyFile::root(device.path());
    let before = bytes(&device);

    assert_eq!(wrong_kind(root.load()), (Kind::Root, Kind::Device));
    // Every other door refuses it for the same reason, and none of them changes it.
    assert!(matches!(
        root.adopt(&secret, Protection::Passphrase(&under)),
        Err(Error::Format {
            source: FormatError::WrongKind { .. },
            ..
        })
    ));
    let new = passphrase("a new passphrase for it");
    assert!(matches!(
        root.migrate(Protection::Passphrase(&under), Protection::Passphrase(&new)),
        Err(Error::Format {
            source: FormatError::WrongKind { .. },
            ..
        })
    ));
    assert_eq!(bytes(&device), before);
}

#[test]
fn a_plain_file_in_the_root_slot_loads_as_plain() {
    // A plain file carries no kind to refuse it by: it loads, and the caller decides what to do with
    // a root key it finds unsealed.
    let dir = TestDir::new();
    let (device, secret) = plain_file(&dir, [4; 32]);
    let root = KeyFile::root(device.path());
    assert_eq!(plain(&root).node_id(), secret.node_id());
}

#[test]
fn a_root_key_is_never_written_plain() {
    let dir = TestDir::new();
    let file = root_file(&dir);
    let secret = Secret::copy_of(&[4; 32]);

    assert!(matches!(
        file.write(&secret, Protection::Plain),
        Err(Error::PlainRoot { .. })
    ));
    assert!(matches!(
        file.adopt(&secret, Protection::Plain),
        Err(Error::PlainRoot { .. })
    ));
    assert!(dir.names().is_empty());

    let under = passphrase("correct horse battery staple");
    file.write(&secret, Protection::Passphrase(&under)).unwrap();
    let sealed = bytes(&file);
    assert!(matches!(
        file.migrate(Protection::Passphrase(&under), Protection::Plain),
        Err(Error::PlainRoot { .. })
    ));
    assert_eq!(bytes(&file), sealed);
    assert_eq!(dir.names(), ["root.key"]);
}

#[test]
fn a_root_key_stays_a_root_key_through_every_migration() {
    let dir = TestDir::new();
    let under = passphrase("correct horse battery staple");
    let new = passphrase("a new passphrase for it");
    // A plain file found in the root slot, sealed: it becomes a root key, not a device key.
    let (device, secret) = plain_file(&dir, [4; 32]);
    let file = KeyFile::root(device.path());
    file.migrate(Protection::Plain, Protection::Passphrase(&under))
        .unwrap();
    assert_eq!(wrong_kind(device.load()), (Kind::Device, Kind::Root));

    // And a new passphrase keeps it one.
    file.migrate(Protection::Passphrase(&under), Protection::Passphrase(&new))
        .unwrap();
    assert_eq!(
        locked(&file).unlock(&new).unwrap().node_id(),
        secret.node_id()
    );
    assert_eq!(wrong_kind(device.load()), (Kind::Device, Kind::Root));
}

#[cfg(unix)]
#[test]
fn a_filesystem_without_hard_links_is_told_apart_from_a_denied_permission() {
    let errno = std::io::Error::from_raw_os_error;
    assert!(lacks_hard_links(&errno(libc::ENOTSUP)));
    assert!(lacks_hard_links(&errno(libc::EPERM)));
    assert!(!lacks_hard_links(&errno(libc::EACCES)));
}
