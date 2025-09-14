use crate::scopes::auth::Error;
use actix_web::{
    FromRequest, HttpRequest,
    dev::Payload,
    web::{Json, Query},
};
use serde::Deserialize;
use std::pin::Pin;
use validator::Validate;

#[derive(Debug, Clone, Copy, Default)]
pub struct ValidatedPayload<T>(pub T);

impl<T> FromRequest for ValidatedPayload<T>
where
    T: for<'de> Deserialize<'de> + Validate + 'static,
{
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self, Self::Error>>>>;

    fn from_request(req: &HttpRequest, payload: &mut Payload) -> Self::Future {
        let fut = Json::<T>::from_request(req, payload);

        Box::pin(async move {
            let json = fut
                .await
                .map_err(|e| Error::InternalServerError(e.to_string()))?;
            json.validate()
                .map_err(|e| Error::BadRequest(e.to_string()))?;

            Ok(ValidatedPayload(json.into_inner()))
        })
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct ValidatedQuery<T>(pub T);

impl<T> FromRequest for ValidatedQuery<T>
where
    T: for<'de> Deserialize<'de> + Validate + 'static,
{
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self, Self::Error>>>>;

    fn from_request(req: &HttpRequest, payload: &mut Payload) -> Self::Future {
        let fut = Query::<T>::from_request(req, payload);

        Box::pin(async move {
            let json = fut
                .await
                .map_err(|e| Error::InternalServerError(e.to_string()))?;
            json.validate()
                .map_err(|e| Error::BadRequest(e.to_string()))?;

            Ok(ValidatedQuery(json.into_inner()))
        })
    }
}
