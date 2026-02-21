use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use utoipa::ToSchema;

use crate::utils::mongodb_serde::*;

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, sqlx::Type)]
pub enum AccountStatus {
    Active,
    Suspended,
    Unverified,
    Locked,
    InvalidCredentials,
}

#[derive(Default, Debug, Clone, PartialEq, Eq, Deserialize, Serialize, FromRow, ToSchema)]
#[schema(example = json!({"id": Some(String::default()), "user_id": String::default(), "password": String::default(), "locked": "false", "created_at": "2026-02-19T22:42:23.467Z"}))]
pub struct Account {
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

    pub password: String,
    pub locked: bool,

    #[sqlx(rename = "createdAt")]
    #[serde(rename = "createdAt")]
    pub created_at: DateTime<Utc>,
}

impl Account {
    pub fn user(user_id: &str) -> Self {
        Self {
            user_id: user_id.into(),
            created_at: Utc::now(),
            ..Default::default()
        }
    }
}
impl Account {
    pub fn with_password(mut self, password: &str) -> Self {
        self.password = password.into();
        self
    }
}
