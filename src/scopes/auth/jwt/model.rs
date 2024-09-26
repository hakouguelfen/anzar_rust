use mongodb::bson::oid::ObjectId;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct RefreshToken {
    #[serde(serialize_with = "serialize_object_id")]
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,

    #[serde(rename = "userId")]
    pub user_id: Option<ObjectId>,

    #[serde(rename = "issuedAt")]
    pub issued_at: usize,

    #[serde(rename = "expireAt")]
    pub expire_at: usize,

    pub hash: String,
    pub valid: bool,
}

impl RefreshToken {
    pub fn new() -> Self {
        RefreshToken {
            id: None,
            user_id: None,
            issued_at: 0,
            expire_at: 0,
            hash: "".to_string(),
            valid: true,
        }
    }
    pub fn with_user_id(mut self, user_id: ObjectId) -> Self {
        let _ = self.user_id.insert(user_id);
        self
    }
    pub fn with_hash(mut self, hash: String) -> Self {
        self.hash = hash;
        self
    }
    pub fn with_issued_at(mut self, issued_at: usize) -> Self {
        self.issued_at = issued_at;
        self
    }
    pub fn with_expire_at(mut self, expire_at: usize) -> Self {
        self.expire_at = expire_at;
        self
    }
}

fn serialize_object_id<S>(id: &Option<ObjectId>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    match id {
        Some(id) => serializer.serialize_str(&id.to_string()),
        None => serializer.serialize_none(),
    }
}
