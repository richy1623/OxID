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
    use std::thread;

    use diesel::r2d2::{ConnectionManager, Pool};
    use rstest::{fixture, rstest};

    use super::*;

    #[fixture]
    #[once]
    pub fn pool() -> Pool<ConnectionManager<PgConnection>> {
        crate::tests::get_test_db_connection_pool("test_authentication_token")
    }

    #[rstest]
    fn test_create_authentication_token(pool: &Pool<ConnectionManager<PgConnection>>) {
        let mut connection = pool.clone().get().unwrap();

        let user = crate::database::model::tests::create_test_user(&mut connection);

        let authentication_token = AuthenticationToken::create_authentication_token(
            &mut connection,
            user.id,
            Duration::from_secs(5),
        )
        .unwrap();

        assert_eq!(authentication_token.user_id, user.id);
        assert!(
            authentication_token
                .expiry_time
                .ge(&Utc::now().naive_local())
        );
        assert!(
            authentication_token
                .expiry_time
                .le(&(Utc::now() + Duration::from_secs(5)).naive_local())
        );

        AuthenticationToken::validate_authentication_token(
            &mut connection,
            authentication_token.token_id,
            authentication_token.user_id,
            authentication_token.token.as_str(),
        )
        .unwrap();
    }

    #[rstest]
    fn test_validate_invalid_token(pool: &Pool<ConnectionManager<PgConnection>>) {
        let mut connection = pool.clone().get().unwrap();

        let user = crate::database::model::tests::create_test_user(&mut connection);

        let authentication_token = AuthenticationToken::create_authentication_token(
            &mut connection,
            user.id,
            Duration::from_secs(5),
        )
        .unwrap();

        assert!(
            AuthenticationToken::validate_authentication_token(
                &mut connection,
                authentication_token.token_id,
                authentication_token.user_id,
                "invalid_token",
            )
            .is_err()
        );
    }

    #[rstest]
    fn test_validate_no_such_token(pool: &Pool<ConnectionManager<PgConnection>>) {
        let mut connection = pool.clone().get().unwrap();

        let user = crate::database::model::tests::create_test_user(&mut connection);

        assert!(
            AuthenticationToken::validate_authentication_token(
                &mut connection,
                uuid::Uuid::now_v7(),
                user.id,
                "no_such_token",
            )
            .is_err()
        );
    }
    
    #[rstest]
    fn test_validate_expired_token(pool: &Pool<ConnectionManager<PgConnection>>) {
        let mut connection = pool.clone().get().unwrap();

        let user = crate::database::model::tests::create_test_user(&mut connection);

        let authentication_token = AuthenticationToken::create_authentication_token(
            &mut connection,
            user.id,
            Duration::ZERO,
        )
        .unwrap();

        thread::sleep(Duration::from_millis(5));

        assert!(
            AuthenticationToken::validate_authentication_token(
                &mut connection,
                authentication_token.token_id,
                authentication_token.user_id,
                authentication_token.token.as_str(),
            )
            .is_err()
        );
    }
}
