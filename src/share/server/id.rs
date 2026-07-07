//! Report id generation: 10 lowercase alphanumeric characters, drawn from a
//! CSPRNG. Kept separate from any actual RNG call so the charset/length
//! contract is unit-testable and the RNG source is swappable (real CSPRNG in
//! production, a fixed byte sequence in tests).

/// Character set report ids are drawn from: lowercase letters + digits (36
/// symbols), chosen for URL-friendliness and to read cleanly out loud.
pub const ID_CHARSET: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";

/// Length of a generated report id, in characters.
pub const ID_LEN: usize = 10;

/// Builds a report id from a stream of random bytes, mapping each byte into
/// `ID_CHARSET` by modulo. The caller supplies at least `ID_LEN` random
/// bytes (typically from a CSPRNG); this function contains no randomness
/// itself, which is what makes it unit-testable.
pub fn id_from_bytes(bytes: &[u8]) -> String {
    bytes
        .iter()
        .take(ID_LEN)
        .map(|b| ID_CHARSET[(*b as usize) % ID_CHARSET.len()] as char)
        .collect()
}

/// Generates a fresh report id using the OS CSPRNG (via `rand`).
pub fn generate_id() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; ID_LEN];
    rand::rng().fill_bytes(&mut bytes);
    id_from_bytes(&bytes)
}

/// Whether `s` is a syntactically valid report id (used to reject
/// obviously-bogus lookups, e.g. path traversal attempts, before touching
/// the filesystem).
pub fn is_valid_id(s: &str) -> bool {
    s.len() == ID_LEN
        && !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn id_from_bytes_has_correct_length_and_charset() {
        let bytes: Vec<u8> = (0..ID_LEN as u8).collect();
        let id = id_from_bytes(&bytes);
        assert_eq!(id.len(), ID_LEN);
        assert!(id.bytes().all(|b| ID_CHARSET.contains(&b)));
    }

    #[test]
    fn id_from_bytes_is_deterministic() {
        let bytes = [1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        assert_eq!(id_from_bytes(&bytes), id_from_bytes(&bytes));
    }

    #[test]
    fn id_from_bytes_truncates_extra_input() {
        let short = [0u8; ID_LEN];
        let long: Vec<u8> = [0u8; ID_LEN].into_iter().chain([99, 99, 99]).collect();
        assert_eq!(id_from_bytes(&short), id_from_bytes(&long));
    }

    #[test]
    fn generated_id_is_valid() {
        let id = generate_id();
        assert!(is_valid_id(&id), "generated id {id} was not valid");
    }

    #[test]
    fn valid_id_accepts_correct_shape() {
        assert!(is_valid_id("ab12cd34ef"));
    }

    #[test]
    fn valid_id_rejects_wrong_length() {
        assert!(!is_valid_id("short"));
        assert!(!is_valid_id("waytoolongtobevalidid"));
        assert!(!is_valid_id(""));
    }

    #[test]
    fn valid_id_rejects_bad_characters() {
        assert!(!is_valid_id("AB12cd34ef")); // uppercase
        assert!(!is_valid_id("../../etc12")); // path traversal
        assert!(!is_valid_id("ab12cd34-f")); // punctuation
    }

    #[test]
    fn two_generated_ids_differ() {
        // Not a strict guarantee, but with a CSPRNG over 36^10 space a
        // collision here would indicate something is badly broken.
        assert_ne!(generate_id(), generate_id());
    }
}
