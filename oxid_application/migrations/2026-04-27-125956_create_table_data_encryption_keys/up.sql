-- Your SQL goes here
CREATE TABLE data_encryption_keys (
    kid UUID PRIMARY KEY NOT NULL DEFAULT uuidv7(),
    encrypted_data_encryption_key BYTEA NOT NULL,
    encryption_nonce BYTEA NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT now(),
    is_active BOOL NOT NULL DEFAULT false
);

CREATE UNIQUE INDEX single_data_encryption_key_active ON data_encryption_keys (is_active) WHERE is_active = true;
