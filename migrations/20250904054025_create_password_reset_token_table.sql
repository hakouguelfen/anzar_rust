-- Add migration script here
CREATE TABLE password_reset_tokens (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    userId TEXT NOT NULL,
    tokenHash TEXT NOT NULL,
    createdAt DATETIME,
    expireAt DATETIME,
    usedAt DATETIME,
    valid BOOLEAN NOT NULL DEFAULT 0
);

