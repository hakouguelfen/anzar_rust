use chrono::{DateTime, Utc};
use serde::{Deserialize, Deserializer, Serialize};
use sqlx::FromRow;

#[derive(Default, Debug, Serialize, Deserialize, Clone, PartialEq, Eq, sqlx::Type)]
pub enum Role {
    #[default]
    User,
    Admin,
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Deserialize, Serialize, FromRow)]
pub struct User {
    #[serde(
        rename = "_id",
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_id"
    )]
    pub id: Option<String>,

    pub username: String,
    pub email: String,
    pub role: Role,
    pub verified: bool,

    #[sqlx(rename = "createdAt")]
    #[serde(rename = "createdAt")]
    pub created_at: DateTime<Utc>,
}

impl User {
    pub fn from_request(user: User) -> Self {
        user
    }
}
impl User {
    pub fn with_id(&mut self, id: &str) {
        self.id = Some(id.into());
    }
    pub fn with_username(mut self, username: &str) -> Self {
        self.username = username.into();
        self
    }
    pub fn with_email(mut self, email: &str) -> Self {
        self.email = email.into();
        self
    }
}

fn deserialize_id<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de::Error;

    let value: Option<serde_json::Value> = Option::deserialize(deserializer)?;
    match value {
        Some(serde_json::Value::String(s)) => Ok(Some(s)),
        Some(val) if val.get("$oid").is_some() => {
            Ok(Some(val["$oid"].as_str().unwrap().to_string()))
        }
        None => Ok(None),
        _ => Err(D::Error::custom("invalid id format")),
    }
}
