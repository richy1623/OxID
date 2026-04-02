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
