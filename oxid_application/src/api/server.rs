use std::{env, io};

use actix_web::{App, HttpServer, web};
use diesel::{
    PgConnection,
    r2d2::{ConnectionManager, Pool},
};

use crate::api::handler::{
    error_handler::{json_error_handler, not_found_handler},
    user_handler::create_user,
};

#[actix_web::main]
async fn main() -> io::Result<()> {
    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");

    let pool: Pool<ConnectionManager<PgConnection>> =
        crate::database::get_connection_pool(&database_url);

    // start HTTP server on port 8080
    HttpServer::new(move || App::new().configure(|c| configure_app(c, pool.clone())))
        .bind(("127.0.0.1", 8080))?
        .run()
        .await
}

pub fn configure_app(cfg: &mut web::ServiceConfig, pool: Pool<ConnectionManager<PgConnection>>) {
    cfg.app_data(web::Data::new(pool))
        .app_data(web::JsonConfig::default().error_handler(json_error_handler))
        .default_service(web::route().to(not_found_handler))
        .service(create_user);
}
