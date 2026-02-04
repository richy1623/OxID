pub mod user;

use thiserror::Error;

#[derive(Error, Debug)]
pub enum DataAccessError {
    #[error("An error occurred while accessing the database")]
    DatabaseError(#[from] diesel::result::Error),
    #[error("An error occurred while performing a crypto operation")]
    CrytpoError,
}

impl From<password_hash::errors::Error> for DataAccessError {
    fn from(_value: password_hash::errors::Error) -> Self {
        DataAccessError::CrytpoError
    }
}
