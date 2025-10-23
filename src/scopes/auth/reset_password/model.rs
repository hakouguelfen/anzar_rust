use crate::utils::mongodb_serde::*;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::prelude::FromRow;

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize, FromRow)]
pub struct PasswordResetToken {
    #[serde(
        rename = "_id",
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_object_id_as_string"
    )]
    pub id: Option<String>,

    #[sqlx(rename = "userId")]
    #[serde(
        rename = "userId",
        default,
        // serialize_with = "serialize_object_id_as_string",
        deserialize_with = "deserialize_object_id"
    )]
    pub user_id: String,

    #[sqlx(rename = "issuedAt")]
    #[serde(rename = "issuedAt")]
    pub issued_at: DateTime<Utc>,
    #[sqlx(rename = "expiresAt")]
    #[serde(rename = "expiresAt")]
    pub expires_at: DateTime<Utc>,
    #[sqlx(rename = "usedAt")]
    #[serde(rename = "usedAt")]
    pub used_at: Option<DateTime<Utc>>,

    pub token: String,
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
            token: String::default(),
            issued_at: Utc::now(),
            expires_at: Utc::now() + chrono::Duration::seconds(86400),
            used_at: None,
            valid: true,
        }
    }
}
impl PasswordResetToken {
    pub fn with_user_id(mut self, user_id: &str) -> Self {
        self.user_id = user_id.into();
        self
    }
    pub fn with_token_hash(mut self, hash: &str) -> Self {
        self.token = hash.into();
        self
    }
    pub fn with_expiray(mut self, expires_at: &chrono::Duration) -> Self {
        self.expires_at = Utc::now() + expires_at.clone();
        self
    }
}
