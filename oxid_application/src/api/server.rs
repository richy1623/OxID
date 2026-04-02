use std::io;

use actix_web::{App, HttpServer, web};
use diesel::{
    PgConnection,
    r2d2::{self, ConnectionManager, Pool},
};

use crate::api::{handler::user_handler::create_user, not_found_handler};

#[actix_web::main]
async fn main() -> io::Result<()> {
    let manager = r2d2::ConnectionManager::<PgConnection>::new("app.db");
    let pool: Pool<ConnectionManager<PgConnection>> = r2d2::Pool::builder()
        .build(manager)
        .expect("database URL should be valid path to SQLite DB file");

    // start HTTP server on port 8080
    HttpServer::new(move || App::new().configure(|c| configure_app(c, pool.clone())))
        .bind(("127.0.0.1", 8080))?
        .run()
        .await
}

pub fn configure_app(cfg: &mut web::ServiceConfig, pool: Pool<ConnectionManager<PgConnection>>) {
    cfg.app_data(web::Data::new(pool))
        .app_data(web::JsonConfig::default().error_handler(crate::api::json_error_handler))
        .default_service(web::route().to(not_found_handler))
        .service(create_user);
}
