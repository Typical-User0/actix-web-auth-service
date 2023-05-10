use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::SaltString;
use argon2::{Argon2, Params, PasswordHasher};
use hex;


use sha3::digest::{FixedOutput};
use sha3::{Digest};
use sha3::{Sha3_512};

lazy_static! {
    static ref ARGON: Argon2<'static> = Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::default(),
        Params::new(
            Params::DEFAULT_M_COST,
            Params::DEFAULT_T_COST,
            num_cpus::get() as u32,
            Some(Params::DEFAULT_OUTPUT_LEN),
        )
        .unwrap(),
    );
}

/// generates random salt with `OsRng` and
/// hashes input bytes using `argon2id` function,
/// parallelism is equal to the number of logical cores
/// other parameters are default
pub fn argon2id_hash(data: &[u8]) -> argon2::password_hash::Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    let hash_result = ARGON.hash_password(data, &salt);

    Ok(hash_result?.to_string())
}

pub fn sha512_hash_with_salt(data: &[u8]) -> String {
    let mut hasher = Sha3_512::new();

    // generate salt
    let salt = SaltString::generate(&mut OsRng);

    let salt_bytes = salt.as_str().as_bytes();

    // hash salt with provided data
    hasher.update(salt_bytes);
    hasher.update(data);

    // 128 chars - hex hash, 22 chars - base64 encoded salt
    let mut result = String::with_capacity(128 + 22);

    result = hex::encode(hasher.finalize_fixed());
    result.push_str(salt.as_str());
    result
}

pub fn sha512_hash_matches(data: &[u8], hash: &str) -> bool {
    let mut hasher = Sha3_512::new();
    let salt_option = hash.get(128..128 + 22);

    if let Some(salt) = salt_option {
        hasher.update(salt.as_bytes());
        hasher.update(data);
        let mut hex_result = String::with_capacity(128);
        hex_result = hex::encode(hasher.finalize_fixed());

        return hex_result == hash[..128].as_ref();
    } else {
        false
    }
}
