use crate::{error::Error, utils::mongodb_serde::*};
use actix_web::{FromRequest, HttpMessage, HttpRequest, dev::Payload};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use std::future::{Ready, ready};

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize, FromRow)]
pub struct Session {
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

    #[sqlx(rename = "createdAt")]
    #[serde(rename = "createdAt")]
    pub created_at: DateTime<Utc>,
    #[sqlx(rename = "expiresAt")]
    #[serde(rename = "expiresAt")]
    pub expires_at: DateTime<Utc>,
    #[sqlx(rename = "updatedAt")]
    #[serde(rename = "updatedAt")]
    pub updated_at: Option<DateTime<Utc>>,

    pub token: String,
}

impl Default for Session {
    fn default() -> Self {
        Self {
            id: None,
            user_id: String::default(),
            created_at: Utc::now(),
            expires_at: Utc::now() + Duration::hours(24),
            updated_at: None,
            token: String::default(),
        }
    }
}

impl Session {
    pub fn from_request(session: Session) -> Self {
        session
    }
}

impl Session {
    pub fn with_user_id(mut self, user_id: &str) -> Self {
        self.user_id = user_id.into();
        self
    }
    pub fn with_token(mut self, token: &str) -> Self {
        self.token = token.into();
        self
    }
}

impl FromRequest for Session {
    type Error = Error;
    type Future = Ready<Result<Self, Error>>;

    fn from_request(req: &HttpRequest, _: &mut Payload) -> Self::Future {
        match req.extensions().get::<Session>() {
            Some(session) => ready(Ok(session.clone())),
            None => ready(Err(Error::InvalidToken {
                token_type: crate::error::TokenErrorType::SessionToken,
                reason: crate::error::InvalidTokenReason::SignatureMismatch,
            })),
        }
    }
}
