use diesel::{ExpressionMethods, QueryDsl, dsl::sql, sql_types::Text};
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use diesel_derive_enum::DbEnum;
use jsonwebtoken::jwk::{Jwk, JwkSet};
use serde::{Deserialize, Serialize};

use crate::{
    crypto::jwt::build_jwk,
    database::{DataAccessError, schema::jwks},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, DbEnum, Serialize, Deserialize)]
#[db_enum(
    existing_type_path = "crate::database::schema::sql_types::JwksState",
    value_style = "snake_case"
)]
pub enum JwkState {
    Revoked,
    Published,
    Active,
}

// fetch published keys
pub async fn fetch_valid_keys(
    connection: &mut AsyncPgConnection,
) -> Result<JwkSet, DataAccessError> {
    let jwks: Vec<(uuid::Uuid, Vec<u8>, String)> = jwks::table
        .filter(jwks::state.eq_any(vec![JwkState::Published, JwkState::Active]))
        .select((
            jwks::kid,
            jwks::encrypted_private_key,
            sql::<Text>("jwt_algorithm::text"),
        ))
        .get_results(connection)
        .await
        .map_err(DataAccessError::from)?;

    Ok(JwkSet {
        keys: jwks
            .iter()
            .map(|(kid, encrypted_private_key, algorithm_string)| {
                build_jwk(kid, encrypted_private_key, algorithm_string)
            })
            .collect::<Result<Vec<Jwk>, DataAccessError>>()?,
    })
}

pub fn fetch_current_jwk() -> Jwk {
    todo!()
}

pub fn create_new_jwk() -> Jwk {
    todo!()
}

pub fn activate_new_jwk() -> Jwk {
    todo!()
}
