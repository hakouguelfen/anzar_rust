use mongodb::bson::oid::ObjectId;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct User {
    #[serde(serialize_with = "serialize_object_id")]
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,
    pub email: String,
    pub password: String,
    #[serde(rename = "refreshToken", skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
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
