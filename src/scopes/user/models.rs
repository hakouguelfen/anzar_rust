use chrono::{DateTime, Utc};
use mongodb::bson::oid::ObjectId;
use serde::{Deserialize, Serialize};

use crate::scopes::auth::Error;

#[derive(Default, Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub enum Role {
    #[default]
    User,
    Admin,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct User {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,

    pub username: String,
    pub email: String,
    pub password: String,

    #[serde(default, rename = "passwordResetCount")]
    pub password_reset_count: u32,

    #[serde(default, rename = "lastPasswordReset")]
    pub last_password_reset: Option<DateTime<Utc>>,

    #[serde(default, rename = "passwordResetWindowStart")]
    pub password_reset_window_start: Option<DateTime<Utc>>,

    #[serde(default)]
    pub role: Role,

    #[serde(default, rename = "isPremium")]
    pub is_premium: bool,

    #[serde(default, rename = "accountLocked")]
    pub account_locked: bool,

    #[serde(default, rename = "failedResetAttempts")]
    pub failed_reset_attempts: u32,
}

impl User {
    pub fn from(user: User) -> Self {
        user
    }

    pub fn set_id(&mut self, id: ObjectId) {
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

#[derive(Debug, Serialize, Deserialize)]
pub struct UserResponse {
    #[serde(rename = "_id")]
    pub id: String,
    pub username: String,
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
