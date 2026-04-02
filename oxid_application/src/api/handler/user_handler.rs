use actix_web::{HttpResponse, Responder, Result, http::StatusCode, post, web};
use diesel_async::{AsyncPgConnection, pooled_connection::deadpool::Pool};
use oxid_service_interface::models::{CreateUserRequest, User};

use crate::{api::handler::get_database_connection, database::model::user::User as UserDbModel};

#[post("/user")]
pub async fn create_user(
    connection_pool: web::Data<Pool<AsyncPgConnection>>,
    // http_request: HttpRequest,
    request: web::Json<CreateUserRequest>,
) -> Result<impl Responder> {
    let create_user_request: CreateUserRequest = request.into_inner();

    let mut connection = get_database_connection(connection_pool).await?;

    let user = UserDbModel::create_user(
        &mut connection,
        &create_user_request.email_address,
        &create_user_request.first_name,
        &create_user_request.surname,
        create_user_request.contact_number.as_deref(),
        create_user_request.address.as_deref(),
        create_user_request.identification.as_deref(),
        &create_user_request.password,
    )
    .await?;

    Ok(HttpResponse::Ok()
        .status(StatusCode::CREATED)
        .json(User::from(user)))
}

#[cfg(test)]
mod tests {
    use actix_web::{App, http::StatusCode};
    use rstest::{fixture, rstest};

    use super::*;

    #[fixture]
    #[once]
    pub fn db_pool() -> Pool<AsyncPgConnection> {
        crate::database::tests::get_test_db_connection_pool("test_user_handler")
    }

    #[rstest]
    #[actix_web::test]
    async fn test_create_user(db_pool: &Pool<AsyncPgConnection>) {
        let mut connection = db_pool.get().await.unwrap();

        let db_pool = db_pool.clone();
        let server = actix_test::start(move || {
            App::new().configure(|c| crate::api::server::configure_app(c, db_pool.clone()))
        });

        let request = server.post("/user");
        let mut response = request
            .insert_header((actix_web::http::header::CONTENT_TYPE, "application/json"))
            .send_body(include_str!(
                "../../../tests/resources/api/payload/CreateUserRequest.json"
            ))
            .await
            .unwrap();

        // Validate the response
        assert_eq!(response.status(), StatusCode::CREATED);
        let user: User = response.json().await.unwrap();
        assert_eq!(user.email_address, "user@example.com");
        assert_eq!(user.first_name, "John");
        assert_eq!(user.surname, "Doe");
        assert_eq!(user.contact_number, Some("+27821234567".to_string()));
        assert_eq!(user.address, Some("123 Main Road, Cape Town".to_string()));
        assert_eq!(user.identification, Some("439405987".to_string()));

        // Validate the DB update
        let user_in_db = UserDbModel::get_user_by_user_id(&mut connection, &user.user_id)
            .await
            .unwrap();
        assert_eq!(User::from(user_in_db), user);
        assert!(
            UserDbModel::validate_login(&mut connection, &user.email_address, "StrongPassword123")
                .await
                .is_ok()
        );
    }

    #[rstest]
    #[actix_web::test]
    async fn test_create_user_duplicate(db_pool: &Pool<AsyncPgConnection>) {
        let mut connection = db_pool.get().await.unwrap();

        let db_pool = db_pool.clone();
        let server = actix_test::start(move || {
            App::new().configure(|c| crate::api::server::configure_app(c, db_pool.clone()))
        });

        // create duplicate user
        let user = crate::database::model::tests::create_test_user(&mut connection).await;

        let request = server.post("/user");
        let response = request
            .insert_header((actix_web::http::header::CONTENT_TYPE, "application/json"))
            .send_json(&CreateUserRequest::new(
                user.email_address,
                "first_name".to_string(),
                "surname".to_string(),
                "password".to_string(),
            ))
            .await
            .unwrap();

        // Validate the response
        assert_eq!(response.status(), StatusCode::CONFLICT);
    }
}
