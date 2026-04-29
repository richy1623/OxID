use oxid_service_interface::models::User as ApiUserModel;

use crate::database::model::user::User;

pub mod authentication_token;
pub mod data_encryption_key;
pub mod jwks;
pub mod user;
pub mod user_permission;

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
    use diesel_async::AsyncPgConnection;
    use uuid::Uuid;

    use crate::database::model::{user::User, user_permission::UserPermissions};

    pub async fn create_test_user(connection: &mut AsyncPgConnection) -> User {
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
        .await
        .unwrap()
    }

    pub async fn assign_test_permissions(
        connection: &mut AsyncPgConnection,
        user: &User,
    ) -> UserPermissions {
        UserPermissions::set_permissions(
            connection,
            &user.id,
            &vec!["test:read", "test:write", "test2:read"],
        )
        .await
        .unwrap();
        UserPermissions::get_permissions(connection, &user.id)
            .await
            .unwrap()
    }
}
