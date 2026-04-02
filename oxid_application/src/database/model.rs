use oxid_service_interface::models::User as ApiUserModel;

use crate::database::model::user::User;

pub mod authentication_token;
pub mod user;
pub mod user_permission;

// #[derive(Error, Debug)]
// pub enum DataAccessErrorNew {
//     #[error("An error occurred while accessing the database")]
//     InternalDatabaseError(#[from] diesel::result::Error),
//     #[error("An error occurred while performing a crypto operation")]
//     CrytpoError,
//     DataItemNotFound,
//     DuplicateEntry,

// }

impl From<User> for ApiUserModel {
    fn from(user: User) -> Self {
        Self {
            user_id: user.id,
            email_address: user.email_address,
            first_name: user.first_name,
            surname: user.surname,
            contact_number: user.contact_number,
            address: user.address,
            identification: user.identification,
        }
    }
}

#[cfg(test)]
pub mod tests {
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
