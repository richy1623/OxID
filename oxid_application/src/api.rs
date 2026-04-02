pub mod handler;
pub mod server;

use crate::database::DataAccessError;
use actix_web::{
    Error as ActixError, HttpRequest,
    error::{
        ErrorConflict, ErrorInternalServerError, ErrorNotFound, ErrorServiceUnavailable,
        ErrorUnauthorized,
    },
};
use actix_web::{HttpResponse, Result, error};
use diesel::{PgConnection, r2d2, result::DatabaseErrorKind};
use serde::Serialize;

type DbPool = r2d2::Pool<r2d2::ConnectionManager<PgConnection>>;

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
            DataAccessError::CrytpoError => {
                ErrorUnauthorized("Incorrect password or  invalid token")
            }
        }
    }
}

#[derive(Serialize)]
pub struct ErrorDetail {
    error: String,
    message: String,
}

pub fn json_error_handler(
    err: error::JsonPayloadError,
    _req: &actix_web::HttpRequest,
) -> error::Error {
    let resp = HttpResponse::BadRequest().json(ErrorDetail {
        error: "Bad Request".to_string(),
        message: err.to_string(),
    });

    error::InternalError::from_response(err, resp).into()
}

pub async fn not_found_handler(http_request: HttpRequest) -> Result<HttpResponse> {
    Ok(HttpResponse::NotFound().json(ErrorDetail {
        error: "Not Found".to_string(),
        message: format!(
            "The requested path or method does not exist: {} {}",
            http_request.method(),
            http_request.path()
        ),
    }))
}
