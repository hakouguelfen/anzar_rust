use chrono::{DateTime, Utc};
use serde::{Deserialize, Deserializer, Serialize};
use sqlx::FromRow;
use validator::Validate;

use crate::error::Error;

#[derive(Default, Debug, Serialize, Deserialize, Clone, PartialEq, Eq, sqlx::Type)]
pub enum Role {
    #[default]
    User,
    Admin,
}

// FIXME don't use validations here
#[derive(Debug, Default, Clone, PartialEq, Eq, Deserialize, Serialize, Validate, FromRow)]
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

    #[serde(default)]
    pub verified: bool,

    #[sqlx(rename = "accountLocked")] // Map database column to struct field
    #[serde(default, rename = "accountLocked")]
    pub account_locked: bool,

    #[sqlx(rename = "failedResetAttempts")] // Map database column to struct field
    #[serde(default, rename = "failedResetAttempts")]
    pub failed_reset_attempts: u8,
}

impl User {
    pub fn from_request(user: User) -> Self {
        user
    }
}
impl User {
    pub fn with_id(&mut self, id: &str) {
        self.id = Some(id.into());
    }
    pub fn with_username(mut self, username: &str) -> Self {
        self.username = username.into();
        self
    }
    pub fn with_email(mut self, email: &str) -> Self {
        self.email = email.into();
        self
    }
    pub fn with_password(mut self, password: &str) -> Self {
        self.password = password.into();
        self
    }
}
impl User {
    pub fn validate(&self) -> Result<(), Error> {
        if self.email.is_empty() {
            return Err(Error::MissingCredentials {
                field: crate::error::CredentialField::Email,
            });
        }
        if self.password.is_empty() {
            return Err(Error::MissingCredentials {
                field: crate::error::CredentialField::Password,
            });
        }
        Ok(())
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UserResponse {
    pub id: String,
    pub username: String,
    pub email: String,

    pub role: Role,
    #[serde(rename = "isPremium")]
    pub is_premium: bool,
    #[serde(rename = "accountLocked")]
    pub account_locked: bool,
    pub verified: bool,
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
            verified: user.verified,
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
