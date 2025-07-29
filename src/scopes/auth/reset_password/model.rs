use chrono::{DateTime, Utc};
use mongodb::bson::oid::ObjectId;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct PasswordResetTokens {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,

    #[serde(rename = "userId")]
    pub user_id: ObjectId,

    #[serde(rename = "tokenHash")]
    pub token_hash: String,

    #[serde(rename = "createdAt")]
    pub issued_at: DateTime<Utc>,

    #[serde(rename = "expireAt")]
    pub expired_at: DateTime<Utc>,

    #[serde(rename = "usedAt")]
    pub used_at: Option<DateTime<Utc>>,

    pub valid: bool,
}

impl Default for PasswordResetTokens {
    fn default() -> Self {
        Self::new()
    }
}
impl PasswordResetTokens {
    pub fn new() -> Self {
        Self {
            id: None,
            user_id: ObjectId::default(),
            token_hash: String::default(),
            issued_at: Utc::now(),
            expired_at: Utc::now() + chrono::Duration::minutes(30),
            used_at: None,
            valid: true,
        }
    }
    pub fn with_user_id(mut self, user_id: ObjectId) -> Self {
        self.user_id = user_id;
        self
    }
    pub fn with_token_hash(mut self, hash: String) -> Self {
        self.token_hash = hash;
        self
    }
}
