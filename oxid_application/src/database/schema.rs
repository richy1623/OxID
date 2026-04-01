// @generated automatically by Diesel CLI.

diesel::table! {
    authentication_tokens (token_id) {
        token_id -> Uuid,
        user_id -> Uuid,
        token_hash -> Text,
        expiry_time -> Timestamp,
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
diesel::joinable!(user_permissions -> users (user_id));

diesel::allow_tables_to_appear_in_same_query!(
    authentication_tokens,
    user_permissions,
    users,
);
