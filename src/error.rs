use actix_web::{
    HttpResponse, ResponseError,
    http::{StatusCode, header::ContentType},
};
use derive_more::Display;
use serde_json::json;

pub type Result<T> = core::result::Result<T, Error>;

#[derive(Debug, Display)]
pub enum Error {
    #[display("An internal error occurred. Please try again later.")]
    _InternalError,

    #[display("Something has occured while proccessing this request")]
    BadRequest,

    #[display("Data Not Found")]
    NotFound,
}

impl ResponseError for Error {
    fn error_response(&self) -> HttpResponse {
        HttpResponse::build(self.status_code())
            .insert_header(ContentType::json())
            .json(json!({"error": self.to_string()}))
    }

    fn status_code(&self) -> StatusCode {
        match self {
            Error::_InternalError => StatusCode::INTERNAL_SERVER_ERROR,
            Error::BadRequest => StatusCode::BAD_REQUEST,
            Error::NotFound => StatusCode::NOT_FOUND,
        }
    }
}
