use std::io::Write;

use crate::crypto::data_encryption::KeyManager;
use crate::database::schema::sql_types::JwkState as JwkStateSqlType;
use crate::database::schema::sql_types::JwtAlgorithm as JwtAlgorithmSqlType;
use crate::{
    crypto::jwt::build_jwk,
    database::{DataAccessError, schema::jwks},
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

pub async fn fetch_valid_keys(
    connection: &mut AsyncPgConnection,
    key_manager: &KeyManager,
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

    let mut keys = Vec::new();
    for (kid, encrypted_private_key, encryption_nonce, algorithm) in jwks {
        let der_encoded_private_key = key_manager
            .decrypt_data(
                &kid,
                &encrypted_private_key,
                encryption_nonce.as_array().unwrap(),
            )
            .await?;

        let jwk = build_jwk(&kid, &der_encoded_private_key, algorithm.0)?;
        keys.push(jwk);
    }

    Ok(JwkSet { keys })
}

// TODO handle no current JWK
pub async fn fetch_current_jwk(
    connection: &mut AsyncPgConnection,
    key_manager: &KeyManager,
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

    let der_encoded_private_key = key_manager
        .decrypt_data(
            &kid,
            &encrypted_private_key,
            encryption_nonce.as_array().unwrap(),
        )
        .await?;

    build_jwk(&kid, &der_encoded_private_key, algorithm.0)
}

pub async fn create_new_jwk(
    connection: &mut AsyncPgConnection,
    key_manager: &KeyManager,
    encoding_key: &EncodingKey,
    encoding_key_algorithm: &Algorithm,
) -> Result<Jwk, DataAccessError> {
    let (kid, encrypted_encoding_key, nonce) =
        key_manager.encrypt_data(encoding_key.inner()).await?;

    let kid: uuid::Uuid = diesel::insert_into(jwks::table)
        .values((
            jwks::encrypted_der_encoded_private_key.eq(encrypted_encoding_key),
            jwks::encryption_nonce.eq(nonce.to_vec()),
            jwks::data_encryption_key_id.eq(kid),
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
