use std::io::Write;

use crate::database::schema::sql_types::JwkState as JwkStateSqlType;
use crate::database::schema::sql_types::JwtAlgorithm as JwtAlgorithmSqlType;
use crate::{
    crypto::jwt::build_jwk,
    database::{DataAccessError, model::data_encryption_key::DataEncryptionKeys, schema::jwks},
};
use aes_gcm::{
    AeadCore, Aes128Gcm, Key, KeyInit, Nonce,
    aead::{AeadMut, OsRng, Payload},
};
use diesel::deserialize::{self, FromSql};
use diesel::pg::{Pg, PgValue};
use diesel::serialize::{self, IsNull, Output, ToSql};
use diesel::{ExpressionMethods, QueryDsl, deserialize::FromSqlRow, expression::AsExpression};
use diesel_async::scoped_futures::ScopedFutureExt;
use diesel_async::{AsyncConnection, AsyncPgConnection, RunQueryDsl};
use diesel_derive_enum::DbEnum;
use jsonwebtoken::{
    Algorithm, EncodingKey,
    jwk::{Jwk, JwkSet},
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, DbEnum, Serialize, Deserialize)]
#[db_enum(existing_type_path = "JwkStateSqlType", value_style = "snake_case")]
pub enum JwkState {
    Revoked,
    Published,
    Active,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, AsExpression, FromSqlRow)]
#[diesel(sql_type = JwtAlgorithmSqlType)]
pub struct JwtAlgorithm(pub Algorithm);
impl ToSql<JwtAlgorithmSqlType, Pg> for JwtAlgorithm {
    fn to_sql<'b>(&'b self, out: &mut Output<'b, '_, Pg>) -> serialize::Result {
        out.write_all(serde_json::to_string(&self.0)?.as_bytes())?;
        Ok(IsNull::No)
    }
}
impl FromSql<JwtAlgorithmSqlType, Pg> for JwtAlgorithm {
    fn from_sql(bytes: PgValue<'_>) -> deserialize::Result<Self> {
        let algorithm_as_string = std::str::from_utf8(bytes.as_bytes())?;
        Ok(JwtAlgorithm(serde_json::from_str(algorithm_as_string)?))
    }
}

// fetch published keys
pub async fn fetch_valid_keys(
    connection: &mut AsyncPgConnection,
    data_encryption_keys: &DataEncryptionKeys,
) -> Result<JwkSet, DataAccessError> {
    let jwks: Vec<(uuid::Uuid, Vec<u8>, Vec<u8>, JwtAlgorithm)> = jwks::table
        .filter(jwks::state.eq_any(vec![JwkState::Published, JwkState::Active]))
        .select((
            jwks::kid,
            jwks::encrypted_der_encoded_private_key,
            jwks::encryption_nonce,
            jwks::algorithm,
        ))
        .get_results(connection)
        .await
        .map_err(DataAccessError::from)?;

    Ok(JwkSet {
        keys: jwks
            .into_iter()
            .map(
                |(kid, encrypted_private_key, encryption_nonce, algorithm)| {
                    build_jwk_from_db_jwks_entry(
                        &kid,
                        &encrypted_private_key,
                        &encryption_nonce,
                        algorithm.0,
                        data_encryption_keys,
                    )
                },
            )
            .collect::<Result<Vec<Jwk>, DataAccessError>>()?,
    })
}

fn build_jwk_from_db_jwks_entry(
    kid: &uuid::Uuid,
    encrypted_private_key: &Vec<u8>,
    encryption_nonce: &Vec<u8>,
    algorithm: Algorithm,
    data_encryption_keys: &DataEncryptionKeys,
) -> Result<Jwk, DataAccessError> {
    let mut cipher = match data_encryption_keys.get_decryption_key(kid) {
        #[allow(deprecated)]
        Some(key) => Ok(Aes128Gcm::new(Key::<Aes128Gcm>::from_slice(key))),
        None => Err(DataAccessError::CryptoError),
    }?;
    let decrypted_private_key = cipher
        .decrypt(
            #[allow(deprecated)]
            Nonce::from_slice(encryption_nonce),
            Payload {
                msg: encrypted_private_key,
                aad: blake3::hash(&encrypted_private_key).as_bytes(),
            },
        )
        .map_err(|_| DataAccessError::CryptoError)?;

    build_jwk(kid, &decrypted_private_key, algorithm)
}

// TODO handle no current JWK
pub async fn fetch_current_jwk(
    connection: &mut AsyncPgConnection,
    data_encryption_keys: &DataEncryptionKeys,
) -> Result<Jwk, DataAccessError> {
    let (kid, encrypted_private_key, encryption_nonce, algorithm): (
        uuid::Uuid,
        Vec<u8>,
        Vec<u8>,
        JwtAlgorithm,
    ) = jwks::table
        .filter(jwks::state.eq(JwkState::Active))
        .select((
            jwks::kid,
            jwks::encrypted_der_encoded_private_key,
            jwks::encryption_nonce,
            jwks::algorithm,
        ))
        .get_result(connection)
        .await
        .map_err(DataAccessError::from)?;

    build_jwk_from_db_jwks_entry(
        &kid,
        &encrypted_private_key,
        &encryption_nonce,
        algorithm.0,
        data_encryption_keys,
    )
}

pub async fn create_new_jwk(
    connection: &mut AsyncPgConnection,
    data_encryption_keys: &DataEncryptionKeys,
    encoding_key: &EncodingKey,
    encoding_key_algorithm: &Algorithm,
) -> Result<Jwk, DataAccessError> {
    // TODO migrate the data_encryption code
    let dek = data_encryption_keys
        .get_active_key()
        .ok_or(DataAccessError::CryptoError)?;
    #[allow(deprecated)]
    let mut cipher = Aes128Gcm::new(Key::<Aes128Gcm>::from_slice(&dek.key));

    let nonce = Aes128Gcm::generate_nonce(&mut OsRng);
    let encrypted_private_key = cipher
        .encrypt(
            #[allow(deprecated)]
            Nonce::from_slice(&nonce),
            Payload {
                msg: encoding_key.inner(),
                aad: blake3::hash(&encoding_key.inner()).as_bytes(),
            },
        )
        .map_err(|_| DataAccessError::CryptoError)?;

    let kid: uuid::Uuid = diesel::insert_into(jwks::table)
        .values((
            jwks::encrypted_der_encoded_private_key.eq(encrypted_private_key),
            jwks::encryption_nonce.eq(nonce.to_vec()),
            jwks::data_encryption_key_id.eq(dek.kid),
            jwks::algorithm.eq(JwtAlgorithm(*encoding_key_algorithm)),
        ))
        .returning(jwks::kid)
        .get_result(connection)
        .await
        .map_err(DataAccessError::from)?;

    build_jwk(
        &kid,
        &encoding_key.inner().to_vec(),
        *encoding_key_algorithm,
    )
}

pub async fn activate_jwk(
    connection: &mut AsyncPgConnection,
    kid: &uuid::Uuid,
) -> Result<usize, DataAccessError> {
    connection
        .transaction(|connection| {
            async move {
                // Update all other jwks to inactive
                diesel::update(jwks::table.filter(jwks::state.eq(JwkState::Active)))
                    .set(jwks::state.eq(JwkState::Published))
                    .execute(connection)
                    .await
                    .map_err(DataAccessError::from)?;

                // Add the new key as active
                diesel::update(jwks::table.filter(jwks::kid.eq(kid)))
                    .set(jwks::state.eq(JwkState::Active))
                    .execute(connection)
                    .await
                    .map_err(DataAccessError::from)
            }
            .scope_boxed()
        })
        .await
}
