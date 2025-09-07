use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::prelude::FromRow;

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize, FromRow)]
pub struct PasswordResetToken {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,

    #[sqlx(rename = "userId")]
    #[serde(rename = "userId")]
    pub user_id: String,

    #[sqlx(rename = "tokenHash")]
    #[serde(rename = "tokenHash")]
    pub token_hash: String,

    #[sqlx(rename = "createdAt")]
    #[serde(rename = "createdAt")]
    pub issued_at: DateTime<Utc>,

    #[sqlx(rename = "expireAt")]
    #[serde(rename = "expireAt")]
    pub expired_at: DateTime<Utc>,

    #[sqlx(rename = "usedAt")]
    #[serde(rename = "usedAt")]
    pub used_at: Option<DateTime<Utc>>,

    pub valid: bool,
}

impl Default for PasswordResetToken {
    fn default() -> Self {
        Self::new()
    }
}
impl PasswordResetToken {
    pub fn new() -> Self {
        Self {
            id: None,
            user_id: String::default(),
            token_hash: String::default(),
            issued_at: Utc::now(),
            expired_at: Utc::now() + chrono::Duration::minutes(30),
            used_at: None,
            valid: true,
        }
    }
    pub fn with_user_id(mut self, user_id: String) -> Self {
        self.user_id = user_id;
        self
    }
    pub fn with_token_hash(mut self, hash: String) -> Self {
        self.token_hash = hash;
        self
    }
}
