use std::time::Duration;

use argon2::{PasswordHash, PasswordVerifier};
use chrono::Utc;
use diesel::{ExpressionMethods, PgConnection, QueryDsl, RunQueryDsl};
use serde::{Deserialize, Serialize};

use crate::{
    crypto::{ARGON2, hash_string},
    database::{
        model::DataAccessError,
        schema::authentication_tokens::{self},
    },
};

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
/// AuthenticationToken : A token used to provide access to a users account
pub struct AuthenticationToken {
    /// User's id
    pub user_id: uuid::Uuid,
    /// The id of the token
    pub token_id: uuid::Uuid,
    /// The secret token
    pub token: String,
    /// User's given name
    pub expiry_time: chrono::NaiveDateTime,
}

impl AuthenticationToken {
    pub fn create_authentication_token(
        connection: &mut PgConnection,
        user_id: uuid::Uuid,
        token_life: Duration,
    ) -> Result<AuthenticationToken, DataAccessError> {
        let mut key_bytes = [0u8; 64];
        getrandom::fill(&mut key_bytes)?;
        let key_hex_string = hex::encode(&key_bytes);
        diesel::insert_into(authentication_tokens::table)
            .values((
                authentication_tokens::user_id.eq(user_id),
                authentication_tokens::token_hash.eq(hash_string(&key_hex_string)?),
                authentication_tokens::expiry_time.eq((Utc::now() + token_life).naive_utc()),
            ))
            .returning((
                authentication_tokens::user_id,
                authentication_tokens::token_id,
                authentication_tokens::expiry_time,
            ))
            .get_result(connection)
            .map_err(DataAccessError::from)
            .map(|(user_id, token_id, expiry_time)| AuthenticationToken {
                user_id,
                token_id,
                expiry_time,
                token: key_hex_string,
            })
        // TODO update API to include token_id
    }

    pub fn validate_authentication_token(
        connection: &mut PgConnection,
        token_id: uuid::Uuid,
        user_id: uuid::Uuid,
        token: &str,
    ) -> Result<(), DataAccessError> {
        let (db_user_id, expiry_time, token_hash): (uuid::Uuid, chrono::NaiveDateTime, String) =
            authentication_tokens::table
                .filter(authentication_tokens::token_id.eq(token_id))
                .select((
                    authentication_tokens::user_id,
                    authentication_tokens::expiry_time,
                    authentication_tokens::token_hash,
                ))
                .first(connection)?;
        // Verify the user is correct
        if user_id != db_user_id {
            return Err(DataAccessError::CrytpoError);
        }
        // Verify that the token is not expired
        if expiry_time < Utc::now().naive_utc() {
            return Err(DataAccessError::CrytpoError);
        }
        // Verify that the token is correct
        ARGON2.verify_password(token.as_bytes(), &PasswordHash::new(&token_hash)?)?;

        Ok(())
    }

    pub fn delete_token(
        connection: &mut PgConnection,
        token_id: uuid::Uuid,
    ) -> Result<usize, DataAccessError> {
        diesel::delete(authentication_tokens::table)
            .filter(authentication_tokens::token_id.eq(token_id))
            .execute(connection)
            .map_err(DataAccessError::from)
    }

    pub fn delete_user_tokens(
        connection: &mut PgConnection,
        user_id: uuid::Uuid,
    ) -> Result<usize, DataAccessError> {
        diesel::delete(authentication_tokens::table)
            .filter(authentication_tokens::user_id.eq(user_id))
            .execute(connection)
            .map_err(DataAccessError::from)
    }

    pub fn delete_expired_tokens(connection: &mut PgConnection) -> Result<usize, DataAccessError> {
        diesel::delete(authentication_tokens::table)
            .filter(authentication_tokens::expiry_time.lt(Utc::now().naive_utc()))
            .execute(connection)
            .map_err(DataAccessError::from)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_name() {}
}
