use zeroize::Zeroizing;

use super::{Passphrase, PassphraseError, nfc};

#[test]
fn an_empty_passphrase_is_refused_through_either_door() {
    assert_eq!(
        Passphrase::new(Zeroizing::new(Vec::new())).unwrap_err(),
        PassphraseError::Empty
    );
    assert_eq!(
        Passphrase::try_from(Zeroizing::new(String::new())).unwrap_err(),
        PassphraseError::Empty
    );
}

#[test]
fn typed_text_is_put_in_nfc_and_otherwise_left_alone() {
    // Composed and decomposed spellings of one visible text are one passphrase; spaces and case are
    // kept, because NFC is the whole of the rule.
    for (typed, form) in [
        ("cafe\u{301} cre\u{300}me", "caf\u{e9} cr\u{e8}me"),
        ("caf\u{e9} cr\u{e8}me", "caf\u{e9} cr\u{e8}me"),
        (" Padded ", " Padded "),
    ] {
        let passphrase = Passphrase::try_from(Zeroizing::new(typed.to_owned())).unwrap();
        assert_eq!(passphrase.as_bytes(), form.as_bytes());
    }
}

#[test]
fn bytes_are_put_in_nfc_the_same_as_typed_text() {
    // The byte door is not a way around the rule: decomposed bytes become the same passphrase.
    let passphrase = Passphrase::new(Zeroizing::new("cafe\u{301}".as_bytes().to_vec())).unwrap();
    assert_eq!(passphrase.as_bytes(), "caf\u{e9}".as_bytes());
}

#[test]
fn bytes_that_are_not_text_are_refused() {
    assert_eq!(
        Passphrase::new(Zeroizing::new(vec![b'a', 0xff, b'b'])).unwrap_err(),
        PassphraseError::NotText
    );
}

#[test]
fn the_worst_case_growth_fits_the_buffer_without_reallocating() {
    // U+1D160 is the case UAX #15 names: four bytes that NFC turns into three four-byte code points.
    let typed = "\u{1d160}".repeat(4);
    let form = nfc(&typed);
    assert_eq!(form.len(), typed.len() * 3);
    assert_eq!(form.capacity(), typed.len() * 3);
}

#[test]
fn debug_never_shows_the_passphrase() {
    let passphrase = Passphrase::try_from(Zeroizing::new("hunter2".to_owned())).unwrap();
    assert_eq!(format!("{passphrase:?}"), "Passphrase(..)");
}
