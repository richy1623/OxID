-- Your SQL goes here
CREATE TABLE authentication_tokens (
    token_id UUID PRIMARY KEY  NOT NULL DEFAULT uuidv7(),
    user_id UUID NOT NULL REFERENCES users(id),
    token_hash TEXT NOT NULL,
    expiry_time TIMESTAMPTZ NOT NULL
);

CREATE INDEX authentication_tokens_index_user_id ON authentication_tokens USING HASH (user_id);
CREATE INDEX authentication_tokens_index_expiry_time ON authentication_tokens (expiry_time);

-- TODO cleanup old tokens
