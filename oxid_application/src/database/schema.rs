// @generated automatically by Diesel CLI.

pub mod sql_types {
    #[derive(diesel::query_builder::QueryId, Clone, diesel::sql_types::SqlType)]
    #[diesel(postgres_type(name = "jwk_state"))]
    pub struct JwkState;

    #[derive(diesel::query_builder::QueryId, Clone, diesel::sql_types::SqlType)]
    #[diesel(postgres_type(name = "jwt_algorithm"))]
    pub struct JwtAlgorithm;
}

diesel::table! {
    authentication_tokens (token_id) {
        token_id -> Uuid,
        user_id -> Uuid,
        token_hash -> Text,
        expiry_time -> Timestamptz,
    }
}

diesel::table! {
    data_encryption_keys (kid) {
        kid -> Uuid,
        encrypted_data_encryption_key -> Bytea,
        encryption_nonce -> Bytea,
        created_at -> Timestamp,
        is_active -> Bool,
    }
}

diesel::table! {
    use diesel::sql_types::*;
    use super::sql_types::JwtAlgorithm;
    use super::sql_types::JwkState;

    jwks (kid) {
        kid -> Uuid,
        encrypted_der_encoded_private_key -> Bytea,
        encryption_nonce -> Bytea,
        data_encryption_key_id -> Uuid,
        algorithm -> JwtAlgorithm,
        created_at -> Timestamp,
        state -> JwkState,
    }
}

diesel::table! {
    user_permissions (user_id, permission) {
        user_id -> Uuid,
        permission -> Text,
    }
}

diesel::table! {
    users (id) {
        id -> Uuid,
        email_address -> Text,
        first_name -> Text,
        surname -> Text,
        identification -> Nullable<Text>,
        contact_number -> Nullable<Text>,
        address -> Nullable<Text>,
        password_hash -> Text,
    }
}

diesel::joinable!(authentication_tokens -> users (user_id));
diesel::joinable!(jwks -> data_encryption_keys (data_encryption_key_id));
diesel::joinable!(user_permissions -> users (user_id));

diesel::allow_tables_to_appear_in_same_query!(
    authentication_tokens,
    data_encryption_keys,
    jwks,
    user_permissions,
    users,
);
