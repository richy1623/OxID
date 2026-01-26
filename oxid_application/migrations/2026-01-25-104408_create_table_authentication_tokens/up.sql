-- Your SQL goes here
CREATE TABLE authentication_tokens (
    user_id UUID NOT NULL REFERENCES users(id),
    token TEXT NOT NULL,
    expiry_time TIMESTAMP NOT NULL,
    PRIMARY KEY (user_id, token)
);

CREATE INDEX authentication_tokens_index_user_id ON authentication_tokens USING HASH (user_id);
CREATE INDEX authentication_tokens_index_expiry_time ON authentication_tokens (expiry_time);

-- TODO cleanup old tokens
