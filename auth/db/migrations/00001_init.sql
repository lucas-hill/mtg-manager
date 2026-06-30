-- +goose Up
CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE users (
    id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    email         text NOT NULL UNIQUE,
    name          text NOT NULL,
    created_at    timestamptz NOT NULL DEFAULT now()
);

--NOTE: This allows us to better group the different providers for our tokens and can allow multiple for each user
CREATE TABLE identities (
    id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id       uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    provider      text NOT NULL,              -- 'password', 'google', 'github'
    provider_id   text,                       -- the provider's user id (null for password)
    password_hash text,                       -- set only for provider='password'
    created_at    timestamptz NOT NULL DEFAULT now(),
    UNIQUE (provider, provider_id)            -- allows for unique combinations and multiple entries with multiple providers
);

CREATE INDEX idx_identities_user ON identities (user_id);

CREATE TABLE refresh_tokens (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash  text NOT NULL UNIQUE,
    expires_at  timestamptz NOT NULL,
    revoked_at  timestamptz,
    created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX idx_refresh_tokens_user ON refresh_tokens (user_id);

-- +goose Down
DROP TABLE refresh_tokens;
DROP TABLE users;
