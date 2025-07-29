use chrono::{DateTime, Utc};
use mongodb::bson::oid::ObjectId;
use serde::{Deserialize, Serialize};

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

    #[serde(default)]
    pub role: Role,

    #[serde(default, rename = "isPremium")]
    pub is_premium: bool,

    #[serde(default, rename = "accountLocked")]
    pub account_locked: bool,

    #[serde(default, rename = "failedResetAttempts")]
    pub failed_reset_attempts: u32,
}

#[derive(Serialize)]
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

impl User {
    pub fn new(user: User) -> Self {
        User {
            id: None,
            username: user.username,
            email: user.email,
            role: Role::User,
            password: "".to_string(),
            is_premium: false,
            password_reset_count: 0,
            last_password_reset: None,
            account_locked: false,
            failed_reset_attempts: 0,
        }
    }

    pub fn with_id(&mut self, id: ObjectId) {
        self.id = Some(id);
    }

    pub fn with_password(mut self, password: String) -> Self {
        self.password = password;
        self
    }

    pub fn as_response(self) -> UserResponse {
        UserResponse {
            // FIXME: dont use unwrap
            id: self.id.unwrap().to_string(),
            email: self.email,
            username: self.username,
            role: self.role,
            is_premium: self.is_premium,
            account_locked: self.account_locked,
        }
    }
}
