use std::future::{Ready, ready};

use crate::core::validators::validate_objectid;
use crate::scopes::auth::Error;

use actix_web::{FromRequest, HttpMessage, HttpRequest, dev::Payload};
use serde::Deserialize;
use validator::Validate;

#[derive(Deserialize, Debug, Clone, Validate)]
pub struct AuthPayload {
    #[validate(length(equal = 24), custom(function = "validate_objectid"))]
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
        match req.extensions().get::<AuthPayload>() {
            Some(payload) => ready(Ok(payload.clone())),
            None => ready(Err(Error::InvalidToken)),
        }
    }
}
