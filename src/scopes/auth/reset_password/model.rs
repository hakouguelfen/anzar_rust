use mongodb::bson::oid::ObjectId;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct PasswordResetTokens {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,

    #[serde(rename = "userId")]
    pub user_id: ObjectId,

    pub token: String,

    #[serde(rename = "createdAt")]
    pub created_at: String,

    #[serde(rename = "expireAt")]
    pub expire_at: String,

    pub used: bool,
}
