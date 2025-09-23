-- Add migration script here
CREATE TABLE users (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    username TEXT NOT NULL UNIQUE,
    email TEXT NOT NULL UNIQUE,
    password TEXT NOT NULL,
    passwordResetCount INTEGER NOT NULL DEFAULT 0,
    lastPasswordReset DATETIME,
    passwordResetWindowStart DATETIME,
    role TEXT NOT NULL,
    isPremium BOOLEAN NOT NULL DEFAULT 0,
    accountLocked BOOLEAN NOT NULL DEFAULT 0,
    failedResetAttempts INTEGER NOT NULL DEFAULT 0
);
