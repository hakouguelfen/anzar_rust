use std::future::{Ready, ready};

use actix_web::{FromRequest, HttpMessage, HttpRequest, dev::Payload};
use chrono::{Duration, Local};
use serde::{Deserialize, Serialize};

use crate::scopes::auth::Error;

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub enum TokenType {
    AccessToken,
    RefreshToken,
}

impl Default for TokenType {
    fn default() -> Self {
        Self::AccessToken
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub exp: usize,
    pub iat: usize,
    pub jti: String,
    pub token_type: TokenType,
}

impl Claims {
    // FIXME: Fix these str types <&String>
    pub fn new(sub: &String, token_type: TokenType, duration: Duration, jti: &String) -> Self {
        Claims {
            sub: sub.to_string(),
            exp: (Local::now() + duration).timestamp() as usize,
            iat: Local::now().timestamp() as usize,
            jti: jti.to_string(),
            token_type,
        }
    }
}

impl FromRequest for Claims {
    type Error = Error;
    type Future = Ready<Result<Self, Error>>;

    fn from_request(req: &HttpRequest, _: &mut Payload) -> Self::Future {
        match req.extensions().get::<Claims>() {
            Some(claims) => ready(Ok(claims.clone())),
            None => ready(Err(Error::InvalidToken)),
        }
    }
}
