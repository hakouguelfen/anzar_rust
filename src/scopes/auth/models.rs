use std::future::{ready, Ready};

use actix_web::{dev::Payload, http::header, FromRequest, HttpRequest};
use serde::Deserialize;

use super::tokens::JwtDecoderBuilder;
use super::Error;
use super::TokenType;

#[derive(Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

#[derive(Debug, Deserialize)]
pub struct TokenQuery {
    pub token: String,
}

#[derive(Debug, Deserialize)]
pub struct EmailRequest {
    pub email: String,
}

#[derive(Deserialize, Debug)]
pub struct AuthPayload {
    pub user_id: String,
    pub refresh_token: String,
}
impl AuthPayload {
    fn from(user_id: String, refresh_token: impl Into<String>) -> Self {
        Self {
            user_id,
            refresh_token: refresh_token.into(),
        }
    }
}
impl FromRequest for AuthPayload {
    type Error = Error;
    type Future = Ready<Result<Self, Error>>;

    fn from_request(req: &HttpRequest, _: &mut Payload) -> Self::Future {
        let refresh_token: &str = req
            .headers()
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .unwrap_or_default();

        let claims_response = JwtDecoderBuilder::new()
            .with_token(refresh_token)
            .with_token_type(TokenType::RefreshToken)
            .build()
            .map_err(|_| Error::InvalidToken)
            .and_then(|claims| {
                if claims.token_type != TokenType::RefreshToken {
                    return Err(Error::InvalidToken);
                }

                Ok(AuthPayload::from(claims.sub, refresh_token))
            });

        ready(claims_response)
    }
}
