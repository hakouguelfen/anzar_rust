use crate::utils::mongodb_serde::*;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::prelude::FromRow;

#[derive(Default, Clone, Debug, PartialEq, Eq, Deserialize, Serialize, FromRow)]
pub struct RefreshToken {
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
        serialize_with = "serialize_object_id_as_string",
        deserialize_with = "deserialize_object_id"
    )]
    pub user_id: String,

    #[sqlx(rename = "issuedAt")]
    #[serde(rename = "issuedAt")]
    pub issued_at: DateTime<Utc>,
    #[sqlx(rename = "expireAt")]
    #[serde(rename = "expireAt")]
    pub expire_at: Option<DateTime<Utc>>,
    #[sqlx(rename = "usedAt")]
    #[serde(rename = "usedAt")]
    pub used_at: Option<DateTime<Utc>>,

    pub jti: String,
    pub hash: String,
    pub valid: bool,
}

impl RefreshToken {
    pub fn with_user_id(mut self, id: String) -> Self {
        self.user_id = id;
        self
    }
    pub fn with_hash(mut self, hash: String) -> Self {
        self.hash = hash;
        self.valid = true;
        self
    }
    pub fn with_jti(mut self, jti: &str) -> Self {
        self.jti = jti.into();
        self
    }
    pub fn with_issued_at(mut self, issued_at: DateTime<Utc>) -> Self {
        self.issued_at = issued_at;
        self
    }
    pub fn with_expire_at(mut self, expire_at: DateTime<Utc>) -> Self {
        let _ = self.expire_at.insert(expire_at);
        self
    }
}
