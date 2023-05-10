use argon2::{Argon2, PasswordHash, PasswordVerifier};

pub fn argon2id_hash_matches(hash: &str, string: &str) -> bool {
    PasswordHash::new(&hash)
        .and_then(|parsed_hash| Argon2::default().verify_password(string.as_bytes(), &parsed_hash))
        .map_or(false, |_| true)
}
