use std::future::{Ready, ready};

use actix_web::{FromRequest, HttpRequest, dev::Payload, web::Data};

use crate::{error::Error, scopes::auth::service::AuthService, startup::AppState};

pub struct AuthServiceExtractor(pub AuthService);

impl FromRequest for AuthServiceExtractor {
    type Error = Error;
    type Future = Ready<Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, _: &mut Payload) -> Self::Future {
        let result = req
            .app_data::<Data<AppState>>()
            .and_then(|state| state.auth_service.lock().ok())
            .and_then(|guard| guard.as_ref().map(|sm| sm.clone()))
            .map(|sm| AuthServiceExtractor(sm.clone()))
            .ok_or(Error::InternalServerError("".into()));

        ready(result)
    }
}
