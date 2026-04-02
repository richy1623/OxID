use actix_web::web;
use diesel::{
    PgConnection,
    r2d2::{ConnectionManager, PooledConnection},
};

use crate::api::DbPool;

pub mod user_handler;

pub fn get_database_connection(
    database_connection_pool: web::Data<DbPool>,
) -> Result<PooledConnection<ConnectionManager<PgConnection>>, actix_web::Error> {
    database_connection_pool.get().map_err(|error| {
        tracing::error!(
            "Internal server error. Failed to establish connection to database: {:?}",
            error
        );
        actix_web::error::ErrorInternalServerError("Failed to establish connection to database")
    })
}
