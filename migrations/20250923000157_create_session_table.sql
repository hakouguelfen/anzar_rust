-- Add migration script here
CREATE TABLE sessions (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    userId TEXT NOT NULL,
    createdAt DATETIME,
    expiresAt DATETIME,
    updatedAt DATETIME,
    token TEXT NOT NULL
);

