use crate::{config::AppState, error::Error, scopes::config::Configuration};
use actix_web::{FromRequest, HttpRequest, dev::Payload, web::Data};
use std::future::{Ready, ready};

pub struct ConfigurationExtractor(pub Configuration);

impl FromRequest for ConfigurationExtractor {
    type Error = Error;
    type Future = Ready<Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, _: &mut Payload) -> Self::Future {
        let result = req
            .app_data::<Data<AppState>>()
            .map(|state| state.configuration.clone())
            .map(|sm| ConfigurationExtractor(sm.clone()))
            .ok_or(Error::InternalServerError("ConfigurationExtractor".into()));

        ready(result)
    }
}
