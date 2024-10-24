use actix_web::{
    http::{header::ContentType, StatusCode},
    HttpResponse, ResponseError,
};
use derive_more::Display;
use serde_json::json;

pub type Result<T> = core::result::Result<T, Error>;

#[derive(Debug, Display)]
pub enum Error {
    #[display("An internal error occurred. Please try again later.")]
    InternalError,

    #[display("Something has occured while proccessing this request")]
    BadRequest,

    #[display("User Creation Error")]
    UserCreationFailure,

    #[display("And error has occured while hashing")]
    HashingFailure,

    #[display("Invalid token")]
    InvalidToken,

    #[display("Wrong credentials")]
    WrongCredentials,

    #[display("Token creation error")]
    TokenCreation,

    #[display("Missing credentials")]
    MissingCredentials,
}

impl ResponseError for Error {
    fn error_response(&self) -> HttpResponse {
        HttpResponse::build(self.status_code())
            .insert_header(ContentType::json())
            .json(json!({"error": self.to_string()}))
    }

    fn status_code(&self) -> StatusCode {
        match self {
            Error::TokenCreation => StatusCode::INTERNAL_SERVER_ERROR,
            Error::HashingFailure => StatusCode::INTERNAL_SERVER_ERROR,
            Error::InternalError => StatusCode::INTERNAL_SERVER_ERROR,

            Error::UserCreationFailure => StatusCode::UNAUTHORIZED,
            Error::InvalidToken => StatusCode::UNAUTHORIZED,
            Error::WrongCredentials => StatusCode::UNAUTHORIZED,

            Error::BadRequest => StatusCode::BAD_REQUEST,
            Error::MissingCredentials => StatusCode::BAD_REQUEST,
        }
    }
}
