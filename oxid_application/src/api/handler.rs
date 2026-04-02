use actix_web::web;
use diesel_async::{
    AsyncPgConnection,
    pooled_connection::deadpool::{Object, Pool},
};
pub mod error_handler;
pub mod user_handler;

pub async fn get_database_connection(
    database_connection_pool: web::Data<Pool<AsyncPgConnection>>,
) -> Result<Object<AsyncPgConnection>, actix_web::Error> {
    database_connection_pool.get().await.map_err(|error| {
        tracing::error!(
            "Internal server error. Failed to establish connection to database: {:?}",
            error
        );
        actix_web::error::ErrorInternalServerError("Failed to establish connection to database")
    })
}
