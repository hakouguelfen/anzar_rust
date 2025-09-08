use chrono::{DateTime, Utc};
use serde::{Deserialize, Deserializer, Serialize};
use sqlx::FromRow;
use validator::Validate;

use crate::scopes::auth::Error;

#[derive(Default, Debug, Serialize, Deserialize, Clone, PartialEq, Eq, sqlx::Type)]
pub enum Role {
    #[default]
    User,
    Admin,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, Validate, FromRow)]
pub struct User {
    #[serde(
        rename = "_id",
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_id"
    )]
    pub id: Option<String>,

    #[validate(length(min = 4, message = "username must be at least 4 characters"))]
    pub username: String,
    #[validate(email)]
    pub email: String,
    #[validate(length(min = 8, message = "password must be at least 8 characters"))]
    pub password: String,

    #[sqlx(rename = "passwordResetCount")] // Map database column to struct field
    #[serde(default, rename = "passwordResetCount")]
    pub password_reset_count: u32,

    #[sqlx(rename = "lastPasswordReset")] // Map database column to struct field
    #[serde(default, rename = "lastPasswordReset")]
    pub last_password_reset: Option<DateTime<Utc>>,

    #[sqlx(rename = "passwordResetWindowStart")] // Map database column to struct field
    #[serde(default, rename = "passwordResetWindowStart")]
    pub password_reset_window_start: Option<DateTime<Utc>>,

    #[serde(default)]
    pub role: Role,

    #[sqlx(rename = "isPremium")] // Map database column to struct field
    #[serde(default, rename = "isPremium")]
    pub is_premium: bool,

    #[sqlx(rename = "accountLocked")] // Map database column to struct field
    #[serde(default, rename = "accountLocked")]
    pub account_locked: bool,

    #[sqlx(rename = "failedResetAttempts")] // Map database column to struct field
    #[serde(default, rename = "failedResetAttempts")]
    pub failed_reset_attempts: u32,
}

impl User {
    pub fn from(user: User) -> Self {
        user
    }

    pub fn set_id(&mut self, id: String) {
        self.id = Some(id);
    }

    pub fn with_password(mut self, password: String) -> Self {
        self.password = password;
        self
    }

    pub fn validate(&self) -> Result<(), Error> {
        if self.email.is_empty() || self.password.is_empty() {
            return Err(Error::MissingCredentials);
        }
        Ok(())
    }
}

#[derive(Debug, Serialize, Deserialize, Validate)]
pub struct UserResponse {
    pub id: String,

    #[validate(length(min = 4, message = "username must be at least 4 characters"))]
    pub username: String,
    #[validate(email)]
    pub email: String,

    pub role: Role,
    #[serde(rename = "isPremium")]
    pub is_premium: bool,
    #[serde(rename = "accountLocked")]
    pub account_locked: bool,
}

impl From<User> for UserResponse {
    fn from(user: User) -> Self {
        Self {
            id: user.id.unwrap_or_default().to_string(),
            username: user.username,
            email: user.email,
            role: user.role,
            is_premium: user.is_premium,
            account_locked: user.account_locked,
        }
    }
}

fn deserialize_id<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de::Error;

    let value: Option<serde_json::Value> = Option::deserialize(deserializer)?;
    match value {
        Some(serde_json::Value::String(s)) => Ok(Some(s)),
        Some(val) if val.get("$oid").is_some() => {
            Ok(Some(val["$oid"].as_str().unwrap().to_string()))
        }
        None => Ok(None),
        _ => Err(D::Error::custom("invalid id format")),
    }
}
