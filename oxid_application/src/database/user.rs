use diesel::{Queryable, Selectable};
use serde::{Deserialize, Serialize};

#[derive(Queryable, Selectable)]
#[diesel(table_name = crate::schema::users)]
/// User : Public user profile information
#[derive(Clone, Default, Debug, PartialEq, Serialize, Deserialize)]
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
}
