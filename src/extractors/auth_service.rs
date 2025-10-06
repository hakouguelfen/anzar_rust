use std::future::{Ready, ready};

use actix_web::{FromRequest, HttpRequest, dev::Payload, web::Data};

use crate::{config::AppState, error::Error, scopes::auth::service::AuthService};

pub struct AuthServiceExtractor(pub AuthService);

impl FromRequest for AuthServiceExtractor {
    type Error = Error;
    type Future = Ready<Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, _: &mut Payload) -> Self::Future {
        let result = req
            .app_data::<Data<AppState>>()
            .map(|state| state.auth_service.clone())
            .map(|sm| AuthServiceExtractor(sm.clone()))
            .ok_or(Error::InternalServerError("AuthServiceExtractor".into()));

        ready(result)
    }
}
