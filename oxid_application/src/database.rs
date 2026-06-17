pub mod model;
pub mod schema;

use diesel_async::AsyncMigrationHarness;
use diesel_async::AsyncPgConnection;
use diesel_async::pooled_connection::AsyncDieselConnectionManager;
use diesel_async::pooled_connection::deadpool::Pool;
use diesel_migrations::EmbeddedMigrations;
use diesel_migrations::MigrationHarness;
use thiserror::Error;

pub const MIGRATIONS: EmbeddedMigrations = diesel_migrations::embed_migrations!();

pub async fn get_connection_pool(database_url: &str) -> Pool<AsyncPgConnection> {
    let manager = AsyncDieselConnectionManager::<AsyncPgConnection>::new(database_url);

    let database_connection_pool = Pool::builder(manager)
        .max_size(20)
        .build()
        .expect("Could not build connection pool");

    AsyncMigrationHarness::new(
        database_connection_pool
            .clone()
            .get()
            .await
            .expect("Failed getting db pool connection"),
    )
    .run_pending_migrations(MIGRATIONS)
    .expect("Failed running migrations");

    database_connection_pool
}

#[derive(Error, Debug, PartialEq)]
pub enum DataAccessError {
    #[error("An error occurred while accessing the database")]
    DatabaseError(#[from] diesel::result::Error),
    #[error("An error occurred while performing a crypto operation")]
    CryptoError,
    #[error("An error occurred")]
    InternalError,
}

impl From<password_hash::Error> for DataAccessError {
    fn from(_value: password_hash::Error) -> Self {
        DataAccessError::CryptoError
    }
}

impl From<password_hash::phc::Error> for DataAccessError {
    fn from(_value: password_hash::phc::Error) -> Self {
        DataAccessError::CryptoError
    }
}

impl From<getrandom::Error> for DataAccessError {
    fn from(_value: getrandom::Error) -> Self {
        DataAccessError::CryptoError
    }
}

#[cfg(test)]
pub mod tests {
    use diesel_async::{AsyncConnection, AsyncPgConnection, RunQueryDsl};

    use crate::database::*;

    pub fn get_test_db_connection_pool(db_name: &str) -> Pool<AsyncPgConnection> {
        let db_name = db_name.to_string();

        std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(3)
                .enable_all()
                .build()
                .expect("Failed to create Tokio runtime");

            rt.block_on(async move {
                let database_url = "postgres://username:password@localhost:5430/postgres";

                let mut conn = AsyncPgConnection::establish(database_url)
                    .await
                    .expect("Error connecting to Postgres server");

                let drop_db_sql = format!("DROP DATABASE IF EXISTS {}", db_name);
                diesel::sql_query(drop_db_sql)
                    .execute(&mut conn)
                    .await
                    .expect("Failed to drop existing database");

                let create_db_sql = format!("CREATE DATABASE {}", db_name);
                diesel::sql_query(create_db_sql)
                    .execute(&mut conn)
                    .await
                    .expect("Failed to create database");

                get_connection_pool(&format!(
                    "postgres://username:password@localhost:5430/{}",
                    db_name
                ))
                .await
            })
        })
        .join()
        .expect("Thread panicked")
    }
}
