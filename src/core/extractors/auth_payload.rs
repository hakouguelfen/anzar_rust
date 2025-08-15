use std::future::{Ready, ready};

use actix_web::{FromRequest, HttpRequest, dev::Payload};
use serde::Deserialize;

use crate::scopes::auth::{Error, tokens::JwtDecoderBuilder};

use super::TokenType;

#[derive(Deserialize, Debug, Clone)]
pub struct AuthPayload {
    pub user_id: String,
    pub refresh_token: String,
    pub jti: String,
}
impl AuthPayload {
    pub fn from(user_id: String, refresh_token: impl Into<String>, jti: String) -> Self {
        Self {
            user_id,
            refresh_token: refresh_token.into(),
            jti,
        }
    }
}
impl FromRequest for AuthPayload {
    type Error = Error;
    type Future = Ready<Result<Self, Error>>;

    fn from_request(req: &HttpRequest, _: &mut Payload) -> Self::Future {
        const X_REFRESH_TOKEN: &str = "x-refresh-token";
        let refresh_token: &str = req
            .headers()
            .get(X_REFRESH_TOKEN)
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

                Ok(AuthPayload::from(claims.sub, refresh_token, claims.jti))
            });

        ready(claims_response)
    }
}
