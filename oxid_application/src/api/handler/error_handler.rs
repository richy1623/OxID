use actix_web::{HttpRequest, HttpResponse, Result, error};
use oxid_service_interface::models::ErrorDetail;

pub fn json_error_handler(
    err: error::JsonPayloadError,
    _req: &actix_web::HttpRequest,
) -> error::Error {
    let resp = HttpResponse::BadRequest().json(ErrorDetail {
        error: "Bad Request".to_string(),
        message: Some(err.to_string()),
    });

    error::InternalError::from_response(err, resp).into()
}

pub async fn not_found_handler(http_request: HttpRequest) -> Result<HttpResponse> {
    Ok(HttpResponse::NotFound().json(ErrorDetail {
        error: "Not Found".to_string(),
        message: Some(format!(
            "The requested path or method does not exist: {} {}",
            http_request.method(),
            http_request.path()
        )),
    }))
}
