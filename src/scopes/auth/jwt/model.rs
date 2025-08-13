use chrono::{DateTime, Utc};
use mongodb::bson::oid::ObjectId;
use serde::{Deserialize, Serialize};

pub struct RefreshTokenFilter {
    pub jti: String,
    pub user_id: ObjectId,
    pub hash: String,
    pub valid: bool,
}

#[derive(Default, Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct RefreshToken {
    #[serde(serialize_with = "serialize_object_id")]
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,

    #[serde(rename = "userId")]
    pub user_id: Option<ObjectId>,

    #[serde(rename = "issuedAt")]
    pub issued_at: DateTime<Utc>,
    #[serde(rename = "expireAt")]
    pub expire_at: Option<DateTime<Utc>>,
    #[serde(rename = "usedAt")]
    pub used_at: Option<DateTime<Utc>>,

    pub jti: String,
    pub hash: String,
    pub valid: bool,
}

// Add build function

impl RefreshToken {
    pub fn with_user_id(mut self, user_id: ObjectId) -> Self {
        let _ = self.user_id.insert(user_id);
        self
    }
    pub fn with_hash(mut self, hash: String) -> Self {
        self.hash = hash;
        self.valid = true;
        self
    }
    pub fn with_jti(mut self, jti: &String) -> Self {
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

// FIXME: remove serializer
fn serialize_object_id<S>(id: &Option<ObjectId>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    match id {
        Some(id) => serializer.serialize_str(&id.to_string()),
        None => serializer.serialize_none(),
    }
}
