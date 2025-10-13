use std::future::{Ready, ready};

use actix_web::{FromRequest, HttpMessage, HttpRequest, dev::Payload};
use chrono::{Duration, Local};
use serde::{Deserialize, Serialize};
use validator::Validate;

use crate::error::Error;
use crate::utils::validation::validate_objectid;

#[derive(Debug, Default, Serialize, Deserialize, Clone, PartialEq)]
pub enum TokenType {
    #[default]
    AccessToken,
    RefreshToken,
}

#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct Claims {
    #[validate(length(equal = 24), custom(function = "validate_objectid"))]
    pub sub: String,
    pub exp: usize,
    pub iat: usize,
    pub jti: String,
    pub token_type: TokenType,
}

impl Claims {
    pub fn new(sub: &str, token_type: TokenType, duration: Duration, jti: &str) -> Self {
        Claims {
            sub: sub.into(),
            exp: (Local::now() + duration).timestamp() as usize,
            iat: Local::now().timestamp() as usize,
            jti: jti.into(),
            token_type,
        }
    }
    pub fn access_token(sub: &str) -> Self {
        Claims {
            sub: sub.into(),
            exp: (Local::now() + Duration::minutes(15)).timestamp() as usize,
            iat: Local::now().timestamp() as usize,
            jti: uuid::Uuid::new_v4().to_string(),
            token_type: TokenType::AccessToken,
        }
    }
    pub fn refresh_token(sub: &str, jti: &str) -> Self {
        Claims {
            sub: sub.into(),
            exp: (Local::now() + Duration::days(15)).timestamp() as usize,
            iat: Local::now().timestamp() as usize,
            jti: jti.into(),
            token_type: TokenType::RefreshToken,
        }
    }
}

impl FromRequest for Claims {
    type Error = Error;
    type Future = Ready<Result<Self, Error>>;

    fn from_request(req: &HttpRequest, _: &mut Payload) -> Self::Future {
        match req.extensions().get::<Claims>() {
            Some(claims) => ready(Ok(claims.clone())),
            None => ready(Err(Error::InvalidToken {
                token_type: crate::error::TokenErrorType::AccessToken,
                reason: crate::error::InvalidTokenReason::SignatureMismatch,
            })),
        }
    }
}
