use argon2::{Argon2, Params, PasswordHasher};
use password_hash::SaltString;
use rand_core::OsRng;
use std::sync::LazyLock;

// Create the static Argon2 instance
pub static ARGON2: LazyLock<Argon2> = LazyLock::new(|| {
    let params = Params::new(256, 4, Params::MIN_P_COST, None).expect("Invalid Argon2 params");

    Argon2::new(
        argon2::Algorithm::default(),
        argon2::Version::default(),
        params,
    )
});

pub fn hash_string(password: &str) -> Result<String, password_hash::Error> {
    hash_bytes(password.as_bytes())
}

pub fn hash_bytes(bytes_to_hash: &[u8]) -> Result<String, password_hash::Error> {
    let salt = SaltString::generate(&mut OsRng);

    let hashed = ARGON2.hash_password(bytes_to_hash, &salt)?;
    Ok(hashed.serialize().to_string())
}
