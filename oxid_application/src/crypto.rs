use argon2::{Argon2, Params};
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
