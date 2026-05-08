use std::time::Duration;

use argon2::{PasswordHash, PasswordVerifier};
use chrono::Utc;
use derive_debug::Dbg;
use diesel::{ExpressionMethods, QueryDsl};
use diesel_async::{AsyncPgConnection, RunQueryDsl};

use crate::{
    crypto::{ARGON2, hash_string},
    database::{
        DataAccessError,
        schema::authentication_tokens::{self},
    },
};

#[derive(Dbg, PartialEq, Eq, Clone)]
/// AuthenticationToken : A token used to provide access to a users account
pub struct AuthenticationToken {
    /// User's id
    pub user_id: uuid::Uuid,
    /// The id of the token
    pub token_id: uuid::Uuid,
    /// The secret token
    #[dbg(placeholder = "****")]
    pub token: String,
    /// The time until which the token is valid
    pub expiry_time: chrono::DateTime<Utc>,
}

impl AuthenticationToken {
    pub async fn create_authentication_token(
        connection: &mut AsyncPgConnection,
        user_id: uuid::Uuid,
        token_life: Duration,
    ) -> Result<AuthenticationToken, DataAccessError> {
        let mut key_bytes = [0u8; 64];
        getrandom::fill(&mut key_bytes)?;
        let key_hex_string: String = hex::encode(&key_bytes);
        diesel::insert_into(authentication_tokens::table)
            .values((
                authentication_tokens::user_id.eq(user_id),
                authentication_tokens::token_hash.eq(hash_string(&key_hex_string)?),
                authentication_tokens::expiry_time.eq(Utc::now() + token_life),
            ))
            .returning((
                authentication_tokens::user_id,
                authentication_tokens::token_id,
                authentication_tokens::expiry_time,
            ))
            .get_result(connection)
            .await
            .map_err(DataAccessError::from)
            .map(|(user_id, token_id, expiry_time)| AuthenticationToken {
                user_id,
                token_id,
                expiry_time,
                token: key_hex_string,
            })
    }

    pub async fn validate_authentication_token(
        connection: &mut AsyncPgConnection,
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
                .first(connection)
                .await?;
        // Verify the user is correct
        if user_id != db_user_id {
            return Err(DataAccessError::CryptoError);
        }
        // Verify that the token is not expired
        if expiry_time < Utc::now().naive_utc() {
            return Err(DataAccessError::CryptoError);
        }
        // Verify that the token is correct
        ARGON2.verify_password(token.as_bytes(), &PasswordHash::new(&token_hash)?)?;

        Ok(())
    }

    pub async fn delete_token(
        connection: &mut AsyncPgConnection,
        token_id: uuid::Uuid,
    ) -> Result<usize, DataAccessError> {
        diesel::delete(authentication_tokens::table)
            .filter(authentication_tokens::token_id.eq(token_id))
            .execute(connection)
            .await
            .map_err(DataAccessError::from)
    }

    pub async fn delete_user_tokens(
        connection: &mut AsyncPgConnection,
        user_id: uuid::Uuid,
    ) -> Result<usize, DataAccessError> {
        diesel::delete(authentication_tokens::table)
            .filter(authentication_tokens::user_id.eq(user_id))
            .execute(connection)
            .await
            .map_err(DataAccessError::from)
    }

    pub async fn delete_expired_tokens(
        connection: &mut AsyncPgConnection,
    ) -> Result<usize, DataAccessError> {
        diesel::delete(authentication_tokens::table)
            .filter(authentication_tokens::expiry_time.lt(Utc::now().naive_utc()))
            .execute(connection)
            .await
            .map_err(DataAccessError::from)
    }
}

#[cfg(test)]
mod tests {
    use std::thread;

    use diesel_async::pooled_connection::deadpool::Pool;
    use rstest::{fixture, rstest};

    use super::*;

    #[fixture]
    #[once]
    pub fn pool() -> Pool<AsyncPgConnection> {
        crate::database::tests::get_test_db_connection_pool("test_authentication_token")
    }

    #[rstest]
    #[tokio::test]
    async fn test_create_authentication_token(pool: &Pool<AsyncPgConnection>) {
        let mut connection = pool.clone().get().await.unwrap();

        let user = crate::database::model::tests::create_test_user(&mut connection).await;

        let authentication_token = AuthenticationToken::create_authentication_token(
            &mut connection,
            user.id,
            Duration::from_secs(5),
        )
        .await
        .unwrap();

        assert_eq!(authentication_token.user_id, user.id);
        assert!(authentication_token.expiry_time.ge(&Utc::now()));
        assert!(
            authentication_token
                .expiry_time
                .le(&(Utc::now() + Duration::from_secs(5)))
        );

        AuthenticationToken::validate_authentication_token(
            &mut connection,
            authentication_token.token_id,
            authentication_token.user_id,
            authentication_token.token.as_str(),
        )
        .await
        .unwrap();
    }

    #[rstest]
    #[tokio::test]
    async fn test_validate_invalid_token(pool: &Pool<AsyncPgConnection>) {
        let mut connection = pool.clone().get().await.unwrap();

        let user = crate::database::model::tests::create_test_user(&mut connection).await;

        let authentication_token = AuthenticationToken::create_authentication_token(
            &mut connection,
            user.id,
            Duration::from_secs(5),
        )
        .await
        .unwrap();

        assert!(
            AuthenticationToken::validate_authentication_token(
                &mut connection,
                authentication_token.token_id,
                authentication_token.user_id,
                "invalid_token",
            )
            .await
            .is_err()
        );
    }

    #[rstest]
    #[tokio::test]
    async fn test_validate_no_such_token(pool: &Pool<AsyncPgConnection>) {
        let mut connection = pool.clone().get().await.unwrap();

        let user = crate::database::model::tests::create_test_user(&mut connection).await;

        assert!(
            AuthenticationToken::validate_authentication_token(
                &mut connection,
                uuid::Uuid::now_v7(),
                user.id,
                "no_such_token",
            )
            .await
            .is_err()
        );
    }

    #[rstest]
    #[tokio::test]
    async fn test_validate_expired_token(pool: &Pool<AsyncPgConnection>) {
        let mut connection = pool.clone().get().await.unwrap();

        let user = crate::database::model::tests::create_test_user(&mut connection).await;

        let authentication_token = AuthenticationToken::create_authentication_token(
            &mut connection,
            user.id,
            Duration::ZERO,
        )
        .await
        .unwrap();

        thread::sleep(Duration::from_millis(5));

        assert!(
            AuthenticationToken::validate_authentication_token(
                &mut connection,
                authentication_token.token_id,
                authentication_token.user_id,
                authentication_token.token.as_str(),
            )
            .await
            .is_err()
        );
    }

    #[rstest]
    #[tokio::test]
    async fn test_delete_token(pool: &Pool<AsyncPgConnection>) {
        let mut connection = pool.clone().get().await.unwrap();

        let user = crate::database::model::tests::create_test_user(&mut connection).await;

        let authentication_token = AuthenticationToken::create_authentication_token(
            &mut connection,
            user.id,
            Duration::from_secs(5),
        )
        .await
        .unwrap();

        AuthenticationToken::delete_token(&mut connection, authentication_token.token_id)
            .await
            .unwrap();

        assert!(
            AuthenticationToken::validate_authentication_token(
                &mut connection,
                authentication_token.token_id,
                authentication_token.user_id,
                authentication_token.token.as_str(),
            )
            .await
            .is_err()
        );
    }

    #[rstest]
    #[tokio::test]
    async fn test_delete_expired_tokens(pool: &Pool<AsyncPgConnection>) {
        let mut connection = pool.clone().get().await.unwrap();

        let user = crate::database::model::tests::create_test_user(&mut connection).await;

        let authentication_token_1 = AuthenticationToken::create_authentication_token(
            &mut connection,
            user.id,
            Duration::from_secs(5),
        )
        .await
        .unwrap();

        let authentication_token_2 = AuthenticationToken::create_authentication_token(
            &mut connection,
            user.id,
            Duration::ZERO,
        )
        .await
        .unwrap();

        let authentication_token_3 = AuthenticationToken::create_authentication_token(
            &mut connection,
            user.id,
            Duration::ZERO,
        )
        .await
        .unwrap();

        thread::sleep(Duration::from_millis(5));

        AuthenticationToken::delete_expired_tokens(&mut connection)
            .await
            .unwrap();

        assert!(
            AuthenticationToken::validate_authentication_token(
                &mut connection,
                authentication_token_1.token_id,
                authentication_token_1.user_id,
                authentication_token_1.token.as_str(),
            )
            .await
            .is_ok()
        );
        assert!(matches!(
            AuthenticationToken::validate_authentication_token(
                &mut connection,
                authentication_token_2.token_id,
                authentication_token_2.user_id,
                authentication_token_2.token.as_str(),
            )
            .await
            .unwrap_err(),
            DataAccessError::DatabaseError(_)
        ));
        assert!(matches!(
            AuthenticationToken::validate_authentication_token(
                &mut connection,
                authentication_token_3.token_id,
                authentication_token_3.user_id,
                authentication_token_3.token.as_str(),
            )
            .await
            .unwrap_err(),
            DataAccessError::DatabaseError(_)
        ));
    }

    #[rstest]
    #[tokio::test]
    async fn test_delete_user_tokens(pool: &Pool<AsyncPgConnection>) {
        let mut connection = pool.clone().get().await.unwrap();

        let user_1 = crate::database::model::tests::create_test_user(&mut connection).await;
        let user_2 = crate::database::model::tests::create_test_user(&mut connection).await;

        let authentication_token_1 = AuthenticationToken::create_authentication_token(
            &mut connection,
            user_1.id,
            Duration::from_secs(5),
        )
        .await
        .unwrap();

        let authentication_token_2 = AuthenticationToken::create_authentication_token(
            &mut connection,
            user_2.id,
            Duration::from_secs(5),
        )
        .await
        .unwrap();

        AuthenticationToken::delete_user_tokens(&mut connection, user_2.id)
            .await
            .unwrap();

        assert!(
            AuthenticationToken::validate_authentication_token(
                &mut connection,
                authentication_token_1.token_id,
                authentication_token_1.user_id,
                authentication_token_1.token.as_str(),
            )
            .await
            .is_ok()
        );
        assert!(matches!(
            AuthenticationToken::validate_authentication_token(
                &mut connection,
                authentication_token_2.token_id,
                authentication_token_2.user_id,
                authentication_token_2.token.as_str(),
            )
            .await
            .unwrap_err(),
            DataAccessError::DatabaseError(_)
        ));
    }
}
