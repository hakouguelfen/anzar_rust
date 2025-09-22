use std::future::{Ready, ready};

use actix_web::{FromRequest, HttpRequest, dev::Payload, web::Data};

use crate::{error::Error, scopes::config::Configuration, startup::AppState};

pub struct ConfigurationExtractor(pub Configuration);

impl FromRequest for ConfigurationExtractor {
    type Error = Error;
    type Future = Ready<Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, _: &mut Payload) -> Self::Future {
        let result = req
            .app_data::<Data<AppState>>()
            .and_then(|state| state.configuration.lock().ok())
            .and_then(|guard| guard.as_ref().map(|sm| sm.clone()))
            .map(|sm| ConfigurationExtractor(sm.clone()))
            .ok_or(Error::InternalServerError("ConfigurationExtractor".into()));

        ready(result)
    }
}
