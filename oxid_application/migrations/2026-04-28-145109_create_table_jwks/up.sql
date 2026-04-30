-- Your SQL goes here
CREATE TYPE jwk_state AS ENUM ('revoked', 'published', 'active');

CREATE TYPE jwt_algorithm AS ENUM (
    'HS256', 'HS384', 'HS512',
    'ES256', 'ES384',
    'RS256', 'RS384', 'RS512',
    'PS256', 'PS384', 'PS512',
    'EdDSA'
);

CREATE TABLE jwks (
    kid UUID PRIMARY KEY NOT NULL DEFAULT uuidv7(),
    encrypted_der_encoded_private_key BYTEA NOT NULL,
    encryption_nonce BYTEA NOT NULL,
    data_encryption_key_id UUID NOT NULL REFERENCES data_encryption_keys (kid) ON DELETE CASCADE,
    -- public_key TEXT NOT NULL,
    algorithm jwt_algorithm NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT now(),
    state jwk_state NOT NULL DEFAULT 'published'
);

CREATE INDEX jwks_index_state ON jwks (state);
CREATE UNIQUE INDEX single_jwk_active ON jwks (state) WHERE state = 'active';
