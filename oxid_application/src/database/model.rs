pub mod authentication_token;
pub mod user;
pub mod user_permission;

use thiserror::Error;

// #[derive(Error, Debug)]
// pub enum DataAccessErrorNew {
//     #[error("An error occurred while accessing the database")]
//     InternalDatabaseError(#[from] diesel::result::Error),
//     #[error("An error occurred while performing a crypto operation")]
//     CrytpoError,
//     DataItemNotFound,
//     DuplicateEntry,

// }

#[derive(Error, Debug)]
pub enum DataAccessError {
    #[error("An error occurred while accessing the database")]
    DatabaseError(#[from] diesel::result::Error),
    #[error("An error occurred while performing a crypto operation")]
    CrytpoError,
}

impl From<password_hash::Error> for DataAccessError {
    fn from(_value: password_hash::Error) -> Self {
        DataAccessError::CrytpoError
    }
}

impl From<password_hash::phc::Error> for DataAccessError {
    fn from(_value: password_hash::phc::Error) -> Self {
        DataAccessError::CrytpoError
    }
}

impl From<getrandom::Error> for DataAccessError {
    fn from(_value: getrandom::Error) -> Self {
        DataAccessError::CrytpoError
    }
}

#[cfg(test)]
mod tests {
    use diesel::PgConnection;
    use uuid::Uuid;

    use crate::database::model::{user::User, user_permission::UserPermissions};

    pub fn create_test_user(connection: &mut PgConnection) -> User {
        User::create_user(
            connection,
            &format!("{}@email.com", &Uuid::now_v7().to_string()),
            "first_name",
            "surname",
            Some("0721234197"),
            Some("address"),
            Some(&Uuid::now_v7().to_string()),
            "password",
        )
        .unwrap()
    }

    pub fn assign_test_permissions(connection: &mut PgConnection, user: &User) -> UserPermissions {
        UserPermissions::set_permissions(
            connection,
            &user.id,
            &vec!["test:read", "test:write", "test2:read"],
        )
        .unwrap();
        UserPermissions::get_permissions(connection, &user.id).unwrap()
    }
}
