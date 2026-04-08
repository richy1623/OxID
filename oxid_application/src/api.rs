pub mod configuration;
pub mod handler;
pub mod server;

use crate::database::DataAccessError;
use actix_web::{Error as ActixError, HttpResponse, error::InternalError, http::StatusCode};
use diesel::result::DatabaseErrorKind;
use oxid_service_interface::models::ErrorDetail;

impl From<DataAccessError> for ActixError {
    fn from(err: DataAccessError) -> Self {
        // 1. Define the components of our error response
        let (status, log_label, detail_msg) = match err {
            DataAccessError::DatabaseError(diesel_err) => match diesel_err {
                diesel::result::Error::NotFound => (
                    StatusCode::NOT_FOUND,
                    "Not Found",
                    "The requested resource could not be located",
                ),
                diesel::result::Error::DatabaseError(kind, info) => match kind {
                    DatabaseErrorKind::UniqueViolation => (
                        StatusCode::CONFLICT,
                        "Unique Violation",
                        "Duplicate entry already exists",
                    ),
                    DatabaseErrorKind::UnableToSendCommand
                    | DatabaseErrorKind::ClosedConnection => (
                        StatusCode::SERVICE_UNAVAILABLE,
                        "DB Connection Lost",
                        "Database connection issue",
                    ),
                    _ => {
                        tracing::error!("Database error: {:?} - {:?}", kind, info);
                        (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "Unhandled DB Error",
                            "An unexpected database error occurred",
                        )
                    }
                },
                diesel::result::Error::BrokenTransactionManager => (
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Transaction Manager Error",
                    "Broken Transaction Manager",
                ),
                error => {
                    tracing::error!("Database error: {:?}", error);
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "Database Error",
                        "An internal database error occurred",
                    )
                }
            },
            DataAccessError::CryptoError => (
                StatusCode::UNAUTHORIZED,
                "Crypto/Auth Error",
                "Incorrect password or invalid token",
            ),
        };

        // 2. Build the JSON body using your external struct
        let body = ErrorDetail {
            error: log_label.to_string(),
            message: Some(detail_msg.to_string()),
        };

        // 3. Build the final Actix error once
        InternalError::from_response(log_label, HttpResponse::build(status).json(body)).into()
    }
}
