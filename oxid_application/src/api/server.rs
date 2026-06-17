use std::io;

use actix_web::{App, HttpServer, web};
use diesel_async::{AsyncPgConnection, pooled_connection::deadpool::Pool};

use crate::{
    api::handler::{
        error_handler::{json_error_handler, not_found_handler},
        user_handler::create_user,
    },
    configuration::AppConfig,
};

#[actix_web::main]
async fn main() -> io::Result<()> {
    let config = AppConfig::new().expect("Failed startup due to invalid config");

    let pool: Pool<AsyncPgConnection> =
        crate::database::get_connection_pool(&config.database_url).await;

    // start HTTP server on port 8080
    HttpServer::new(move || {
        App::new().configure(|c| configure_app(c, config.clone(), pool.clone()))
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}

pub fn configure_app(
    cfg: &mut web::ServiceConfig,
    config: AppConfig,
    pool: Pool<AsyncPgConnection>,
) {
    cfg.app_data(web::Data::new(pool))
        .app_data(web::Data::new(config))
        .app_data(web::JsonConfig::default().error_handler(json_error_handler))
        .default_service(web::route().to(not_found_handler))
        .service(create_user);
}
