use crate::{
    crypto::{ARGON2, hash_string},
    database::{DataAccessError, schema::users},
};
use argon2::{PasswordHash, PasswordVerifier};
use derive_debug::Dbg;
use diesel::{
    ExpressionMethods, Insertable, PgConnection, QueryDsl, Queryable, RunQueryDsl, Selectable,
    SelectableHelper,
};

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
    pub fn create_user(
        connection: &mut PgConnection,
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
            .map_err(DataAccessError::from)
    }

    pub fn get_user_by_email_address(
        connection: &mut PgConnection,
        email_address: &str,
    ) -> Result<User, DataAccessError> {
        users::table
            .filter(users::email_address.eq(email_address))
            .select(User::as_select())
            .first(connection)
            .map_err(DataAccessError::from)
    }

    pub fn get_user_by_user_id(
        connection: &mut PgConnection,
        user_id: &uuid::Uuid,
    ) -> Result<User, DataAccessError> {
        users::table
            .find(user_id)
            .select(User::as_select())
            .first(connection)
            .map_err(DataAccessError::from)
    }

    pub fn validate_login(
        connection: &mut PgConnection,
        email_address: &str,
        password: &str,
    ) -> Result<User, DataAccessError> {
        let user: User = users::table
            .filter(users::email_address.eq(email_address))
            .select(User::as_select())
            .first(connection)?;
        ARGON2.verify_password(
            password.as_bytes(),
            &PasswordHash::new(&user.password_hash)?,
        )?;
        Ok(user)
    }
}

#[cfg(test)]
mod tests {
    use diesel::r2d2::{ConnectionManager, Pool};
    use rstest::{fixture, rstest};

    use super::*;

    #[fixture]
    #[once]
    pub fn pool() -> Pool<ConnectionManager<PgConnection>> {
        crate::tests::get_test_db_connection_pool("test_user")
    }

    #[rstest]
    fn test_create_user(pool: &Pool<ConnectionManager<PgConnection>>) {
        let mut connection = pool.clone().get().unwrap();

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
        .unwrap();

        assert_eq!(user.email_address, "email@noreply.com");
        assert_eq!(user.first_name, "name");
        assert_eq!(user.surname, "surname");
        assert_eq!(user.contact_number, Some("0721234567".to_string()));
        assert_eq!(user.address, Some("some address".to_string()));
        assert_eq!(user.identification, Some("id_number".to_string()));
        User::validate_login(&mut connection, "email@noreply.com", "password").unwrap();

        assert!(
            User::validate_login(&mut connection, "email@noreply.com", "invalid password").is_err()
        );

        assert_eq!(
            User::get_user_by_email_address(&mut connection, "email@noreply.com").unwrap(),
            user
        );

        assert_eq!(
            User::get_user_by_user_id(&mut connection, &user.id).unwrap(),
            user
        );
    }

    #[rstest]
    fn test_create_duplicate_user(pool: &Pool<ConnectionManager<PgConnection>>) {
        let mut connection = pool.clone().get().unwrap();

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
            .is_err()
        );
    }
}
