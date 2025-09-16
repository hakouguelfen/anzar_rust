use chrono::{DateTime, Utc};
use mongodb::bson::oid::ObjectId;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
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

fn serialize_object_id_as_string<S>(id: &String, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    if let Ok(oid) = ObjectId::parse_str(id) {
        serializer.serialize_some(&oid)
    } else {
        serializer.serialize_some(id)
    }
}

fn deserialize_object_id_as_string<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: Deserializer<'de>,
{
    let oid: Option<ObjectId> = Option::deserialize(deserializer)?;
    Ok(oid.map(|o| o.to_hex()))
}

fn deserialize_object_id<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let oid: ObjectId = ObjectId::deserialize(deserializer)?;
    Ok(oid.to_hex())
    // let bson: Bson = Bson::deserialize(deserializer)?;
    // match bson {
    //     Bson::ObjectId(oid) => Ok(oid.to_hex()),
    //     Bson::String(s) => Ok(s),
    //     other => Err(serde::de::Error::custom(format!(
    //         "unexpected _id type: {:?}",
    //         other
    //     ))),
    // }
}
