-- Your SQL goes here
CREATE TABLE users (
    id UUID PRIMARY KEY NOT NULL DEFAULT uuidv7(),
    email TEXT NOT NULL,
    first_name TEXT NOT NULL,
    surname TEXT NOT NULL,
    identification TEXT,
    contact_number TEXT,
    address TEXT,
    password_hash TEXT NOT NULL
);

CREATE UNIQUE INDEX users_index_unique_email ON users (email);
