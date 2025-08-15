use actix_web::{FromRequest, HttpMessage, HttpRequest, dev::Payload};
use std::future::{Ready, ready};

use crate::scopes::{auth::Error, user::User};

pub struct AuthenticatedUser(pub User);

impl FromRequest for AuthenticatedUser {
    type Error = Error;
    type Future = Ready<Result<Self, Error>>;

    fn from_request(req: &HttpRequest, _: &mut Payload) -> Self::Future {
        match req.extensions().get::<User>() {
            Some(user) => ready(Ok(AuthenticatedUser(user.clone()))),
            None => ready(Err(Error::InvalidCredentials)),
        }
    }
}
