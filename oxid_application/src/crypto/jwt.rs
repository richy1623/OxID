use std::time::Duration;

use chrono::Utc;
use jsonwebtoken::{
    Algorithm, AlgorithmFamily, EncodingKey,
    jwk::{Jwk, JwkSet, KeyAlgorithm},
};
use serde::{Deserialize, Serialize};

use crate::{configuration::AppConfig, database::DataAccessError};

/// Represents the Registered Claim Names for a JSON Web Token (JWT).
#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    /// The **Expiration Time**.
    /// A UTC timestamp (seconds) after which the token must not be accepted.
    pub exp: usize,

    /// The **Issued At** time.
    /// A UTC timestamp (seconds) indicating when the JWT was generated.
    pub iat: usize,

    /// The **Subject**.
    /// The principal that is the subject of the JWT (e.g., a User ID).
    pub sub: String,

    /// A list of permissions or scopes assigned to the subject.
    ///
    /// Each string typically represents a specific capability or access level,
    /// such as `"users:read"` or `"admin"`. This is used during the
    /// authorization process to verify if the user can access a specific resource.
    pub perms: Vec<String>,
}

impl Claims {
    /// Creates a new set of claims with a specified lifespan, subject, and permissions.
    ///
    /// This constructor automatically handles the generation of the `iat` (Issued At)
    /// and `exp` (Expiration) timestamps using the current UTC time.
    ///
    /// # Arguments
    ///
    /// * `token_lifespan` - A `Duration` representing how long the token remains valid.
    /// * `subject` - A string slice identifying the principal (e.g., User ID) the token refers to.
    /// * `permissions` - A list of access scopes or roles assigned to this user.
    ///
    /// # Example
    ///
    /// ```
    /// # use oxid_application::crypto::jwt::Claims;
    /// # use std::time::Duration;
    /// let claims = Claims::new(Duration::from_secs(60*60*2), "019d6e27-cf95-7825-b9c6-24d6cd9f3d07", vec!["users:read".to_string(), "users:write".to_string(), "test".to_string()]);
    /// ```
    pub fn new(token_lifespan: Duration, subject: &str, permissions: Vec<String>) -> Self {
        let now = Utc::now();
        Self {
            exp: (now + token_lifespan).timestamp() as usize,
            iat: now.timestamp() as usize,
            sub: subject.to_string(),
            perms: permissions,
        }
    }
}

pub fn build_jwk(
    kid: &uuid::Uuid,
    der_key: &Vec<u8>,
    algorithm: Algorithm,
) -> Result<Jwk, DataAccessError> {
    let encoding_key = match algorithm.family() {
        AlgorithmFamily::Hmac => EncodingKey::from_secret(der_key),
        AlgorithmFamily::Rsa => EncodingKey::from_rsa_der(der_key),
        AlgorithmFamily::Ec => EncodingKey::from_ec_der(der_key),
        AlgorithmFamily::Ed => EncodingKey::from_ed_der(der_key),
    };

    let mut jwk = Jwk::from_encoding_key(&encoding_key, algorithm)
        .map_err(|_| DataAccessError::CryptoError)?;
    jwk.common.key_id = Some(kid.to_string());
    jwk.common.key_algorithm = serde_json::to_string(&algorithm)
        .ok()
        .map(|algorithm_string| serde_json::from_str::<KeyAlgorithm>(&algorithm_string).ok())
        .flatten();

    Ok(jwk)
}

pub static JWT_ENCODING_ALGORITHM: Algorithm = Algorithm::EdDSA;

pub fn fetch_jwks(_configuration: AppConfig) -> JwkSet {
    JwkSet { keys: vec![] }
}

#[cfg(test)]
mod tests {
    use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation};
    use rstest::{fixture, rstest};

    use super::*;

    #[fixture]
    #[once]
    pub fn keys() -> (EncodingKey, DecodingKey) {
        (
            EncodingKey::from_ed_pem(include_bytes!(
                "../../../oxid_application/tests/resources/key/private_key.pem"
            ))
            .expect("Invalid Private Key"),
            DecodingKey::from_ed_pem(include_bytes!(
                "../../../oxid_application/tests/resources/key/public_key.pem"
            ))
            .expect("Invalid Public Key"),
        )
    }

    #[rstest]
    fn test_create_jwt(keys: &(EncodingKey, DecodingKey)) {
        let (encoding_key, decoding_key) = keys;
        let permissions = vec![
            "users:read".to_string(),
            "users:write".to_string(),
            "test".to_string(),
        ];

        let encoded_jwt = jsonwebtoken::encode(
            &Header::new(JWT_ENCODING_ALGORITHM),
            &Claims::new(
                Duration::from_secs(15),
                "019d6e27-cf95-7825-b9c6-24d6cd9f3d07",
                permissions.clone(),
            ),
            encoding_key,
        )
        .unwrap();

        dbg!(&encoded_jwt);

        let decode_jwt = jsonwebtoken::decode::<Claims>(
            &encoded_jwt,
            &decoding_key,
            &Validation::new(JWT_ENCODING_ALGORITHM),
        )
        .unwrap();

        assert!(
            decode_jwt.claims.exp > Utc::now().timestamp() as usize
                && decode_jwt.claims.exp <= Utc::now().timestamp() as usize + 15
        );
        assert!(decode_jwt.claims.iat >= Utc::now().timestamp() as usize);
        assert_eq!(
            decode_jwt.claims.sub,
            "019d6e27-cf95-7825-b9c6-24d6cd9f3d07"
        );
        assert!(decode_jwt.claims.iat >= Utc::now().timestamp() as usize);
        assert_eq!(decode_jwt.claims.perms, permissions);
    }
}
