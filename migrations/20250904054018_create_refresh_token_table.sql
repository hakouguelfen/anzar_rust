-- Add migration script here
CREATE TABLE refresh_token (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    userId TEXT NOT NULL,
    issuedAt DATETIME,
    expireAt DATETIME,
    usedAt DATETIME,
    jti TEXT NOT NULL,
    hash TEXT NOT NULL,
    valid BOOLEAN NOT NULL DEFAULT 0
);

