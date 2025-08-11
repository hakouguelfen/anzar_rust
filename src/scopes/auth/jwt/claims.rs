use std::future::{Ready, ready};

use actix_web::{FromRequest, HttpRequest, dev::Payload, http::header};
use chrono::{Duration, Local};
use serde::{Deserialize, Serialize};

use crate::scopes::auth::Error;
use crate::scopes::user::Role;

use super::tokens::JwtDecoderBuilder;

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

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub exp: usize,
    pub iat: usize,
    pub token_type: TokenType,
    pub role: Role,
}

impl Claims {
    pub fn new(sub: &String, token_type: TokenType, role: &Role, duration: Duration) -> Self {
        Claims {
            sub: sub.to_string(),
            exp: (Local::now() + duration).timestamp() as usize,
            iat: Local::now().timestamp() as usize,
            token_type,
            role: role.clone(),
        }
    }
}

impl FromRequest for Claims {
    type Error = Error;
    type Future = Ready<Result<Self, Error>>;

    fn from_request(req: &HttpRequest, _: &mut Payload) -> Self::Future {
        let access_token: &str = req
            .headers()
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .unwrap_or_default();

        let claims_response = JwtDecoderBuilder::new()
            .with_token(access_token)
            .with_token_type(TokenType::AccessToken)
            .build()
            .map_err(|_| Error::InvalidToken)
            .and_then(|claims| {
                if claims.token_type != TokenType::AccessToken {
                    return Err(Error::InvalidToken);
                }
                Ok(claims)
            });

        ready(claims_response)
    }
}
