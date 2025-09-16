use chrono::{DateTime, Utc};
use mongodb::bson::oid::ObjectId;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
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
        serialize_with = "serialize_object_id_as_string",
        deserialize_with = "deserialize_object_id"
    )]
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
}
impl PasswordResetToken {
    pub fn with_user_id(mut self, user_id: String) -> Self {
        self.user_id = user_id;
        self
    }
    pub fn with_token_hash(mut self, hash: String) -> Self {
        self.token_hash = hash;
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
