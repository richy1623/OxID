use crate::{
    crypto::{ARGON2, hash_string},
    database::{DataAccessError, schema::users},
};
use argon2::{PasswordHash, PasswordVerifier};
use derive_debug::Dbg;
use diesel::{ExpressionMethods, Insertable, QueryDsl, Queryable, Selectable, SelectableHelper};
use diesel_async::{AsyncPgConnection, RunQueryDsl};

#[derive(Queryable, Selectable, Insertable, Dbg, PartialEq, Eq, Clone)]
#[diesel(table_name = crate::database::schema::users)]
/// User : Public user profile information
pub struct User {
    /// User's id (Database Primary Key)
    pub id: uuid::Uuid,
    /// User's email address
    pub email_address: String,
    /// User's given name
    pub first_name: String,
    /// User's family name
    pub surname: String,
    /// User's contact phone number
    pub contact_number: Option<String>,
    /// User's address
    pub address: Option<String>,
    /// Optional identification number (e.g. passport number)
    pub identification: Option<String>,
    /// The ARGON2 hash of the users password
    #[dbg(placeholder = "****")]
    pub password_hash: String,
}

impl User {
    pub async fn create_user(
        connection: &mut AsyncPgConnection,
        email_address: &str,
        first_name: &str,
        surname: &str,
        contact_number: Option<&str>,
        address: Option<&str>,
        identification: Option<&str>,
        password: &str,
    ) -> Result<User, DataAccessError> {
        diesel::insert_into(users::table)
            .values((
                users::email_address.eq(email_address),
                users::first_name.eq(first_name),
                users::surname.eq(surname),
                users::contact_number.eq(contact_number),
                users::address.eq(address),
                users::password_hash.eq(hash_string(&password)?),
                users::identification.eq(identification),
            ))
            .returning(User::as_returning())
            .get_result(connection)
            .await
            .map_err(DataAccessError::from)
    }

    pub async fn get_user_by_email_address(
        connection: &mut AsyncPgConnection,
        email_address: &str,
    ) -> Result<User, DataAccessError> {
        users::table
            .filter(users::email_address.eq(email_address))
            .select(User::as_select())
            .first(connection)
            .await
            .map_err(DataAccessError::from)
    }

    pub async fn get_user_by_user_id(
        connection: &mut AsyncPgConnection,
        user_id: &uuid::Uuid,
    ) -> Result<User, DataAccessError> {
        users::table
            .find(user_id)
            .select(User::as_select())
            .first(connection)
            .await
            .map_err(DataAccessError::from)
    }

    pub async fn validate_login(
        connection: &mut AsyncPgConnection,
        email_address: &str,
        password: &str,
    ) -> Result<User, DataAccessError> {
        let user: User = users::table
            .filter(users::email_address.eq(email_address))
            .select(User::as_select())
            .first(connection)
            .await?;
        ARGON2.verify_password(
            password.as_bytes(),
            &PasswordHash::new(&user.password_hash)?,
        )?;
        Ok(user)
    }
}

#[cfg(test)]
mod tests {
    use diesel_async::pooled_connection::deadpool::Pool;
    use rstest::{fixture, rstest};

    use super::*;

    #[fixture]
    #[once]
    pub fn pool() -> Pool<AsyncPgConnection> {
        crate::database::tests::get_test_db_connection_pool("test_user")
    }

    #[rstest]
    #[tokio::test]
    async fn test_create_user(pool: &Pool<AsyncPgConnection>) {
        let mut connection = pool.clone().get().await.unwrap();

        let user = User::create_user(
            &mut connection,
            "email@noreply.com",
            "name",
            "surname",
            Some("0721234567"),
            Some("some address"),
            Some("id_number"),
            "password",
        )
        .await
        .unwrap();

        assert_eq!(user.email_address, "email@noreply.com");
        assert_eq!(user.first_name, "name");
        assert_eq!(user.surname, "surname");
        assert_eq!(user.contact_number, Some("0721234567".to_string()));
        assert_eq!(user.address, Some("some address".to_string()));
        assert_eq!(user.identification, Some("id_number".to_string()));
        User::validate_login(&mut connection, "email@noreply.com", "password")
            .await
            .unwrap();

        assert!(
            User::validate_login(&mut connection, "email@noreply.com", "invalid password")
                .await
                .is_err()
        );

        assert_eq!(
            User::get_user_by_email_address(&mut connection, "email@noreply.com")
                .await
                .unwrap(),
            user
        );

        assert_eq!(
            User::get_user_by_user_id(&mut connection, &user.id)
                .await
                .unwrap(),
            user
        );
    }

    #[rstest]
    #[tokio::test]
    async fn test_create_duplicate_user(pool: &Pool<AsyncPgConnection>) {
        let mut connection = pool.clone().get().await.unwrap();

        // Initial user
        User::create_user(
            &mut connection,
            "email2@noreply.com",
            "name",
            "surname",
            Some("0721234567"),
            Some("some address"),
            Some("id_number"),
            "password",
        )
        .await
        .unwrap();

        // Duplicate user fails
        assert!(
            User::create_user(
                &mut connection,
                "email2@noreply.com",
                "name",
                "surname",
                Some("0721234567"),
                Some("some address"),
                Some("id_number"),
                "password",
            )
            .await
            .is_err()
        );
    }
}
