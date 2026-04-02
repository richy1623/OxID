pub mod handler;
pub mod server;

use crate::database::DataAccessError;
use actix_web::{
    Error as ActixError,
    error::{
        ErrorConflict, ErrorInternalServerError, ErrorNotFound, ErrorServiceUnavailable,
        ErrorUnauthorized,
    },
};
use diesel::result::DatabaseErrorKind;

impl From<DataAccessError> for ActixError {
    fn from(err: DataAccessError) -> Self {
        match err {
            DataAccessError::DatabaseError(diesel_err) => match diesel_err {
                diesel::result::Error::NotFound => ErrorNotFound("Resource not found"),
                diesel::result::Error::DatabaseError(kind, info) => match kind {
                    DatabaseErrorKind::UniqueViolation => ErrorConflict("Duplicate entry"),
                    DatabaseErrorKind::UnableToSendCommand
                    | DatabaseErrorKind::ClosedConnection => {
                        ErrorServiceUnavailable("Database connection issue")
                    }
                    _ => {
                        tracing::error!("Database error: {:?} - {:?}", kind, info);
                        ErrorInternalServerError("Database error")
                    }
                },
                diesel::result::Error::BrokenTransactionManager => ErrorServiceUnavailable(
                    "Broken Transaction Manager, likely due to database connection issue",
                ),
                error => {
                    tracing::error!("Database error: {:?}", error);
                    ErrorInternalServerError("Database error")
                }
            },
            DataAccessError::CryptoError => {
                ErrorUnauthorized("Incorrect password or invalid token")
            }
        }
    }
}
