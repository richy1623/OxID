-- Your SQL goes here
CREATE TABLE user_permissions (
    user_id UUID NOT NULL REFERENCES users(id),
    permission TEXT NOT NULL,
    PRIMARY KEY (user_id, permission)
);

CREATE INDEX user_permissions_index_user_id ON user_permissions USING HASH (user_id);
