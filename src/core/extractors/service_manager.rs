use std::future::{Ready, ready};

use actix_web::{FromRequest, HttpRequest, dev::Payload, web::Data};

use crate::{
    core::repository::repository_manager::ServiceManager, scopes::auth::Error, startup::AppState,
};

pub struct ServiceManagerExtractor(pub ServiceManager);

impl FromRequest for ServiceManagerExtractor {
    type Error = Error;
    type Future = Ready<Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, _: &mut Payload) -> Self::Future {
        // let result = req
        //     .app_data::<Data<AppState>>()
        //     .and_then(|state| state.service_manager.lock().ok())
        // .and_then(|guard| guard.as_ref().map(|sm| sm.clone()))
        //     .map(|sm| ServiceManagerExtractor(sm.clone()))
        //     .ok_or(Error::InternalServerError);
        //
        // ready(result)

        let app_state = req.app_data::<Data<AppState>>();

        match app_state {
            Some(state) => match state.service_manager.lock() {
                Ok(guard) => match guard.as_ref() {
                    Some(service_manager) => {
                        ready(Ok(ServiceManagerExtractor(service_manager.clone())))
                    }
                    None => ready(Err(Error::InternalServerError)),
                },
                Err(_) => ready(Err(Error::InternalServerError)),
            },
            None => ready(Err(Error::InternalServerError)),
        }
    }
}
