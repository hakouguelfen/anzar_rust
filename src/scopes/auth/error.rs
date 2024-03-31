use actix_web::{HttpResponse, ResponseError};

#[derive(Debug)]
pub enum AuthError {
    InvalidToken,
    WrongCredentials,
    TokenCreation,
    MissingCredentials,
}

impl ResponseError for AuthError {
    fn error_response(self) -> HttpResponse {
        match self {
            AuthError::WrongCredentials => HttpResponse::UNAUTHORIZED.json("Wrong credentials"),
            AuthError::MissingCredentials => HttpResponse::BAD_REQUEST.json("Missing credentials"),
            AuthError::TokenCreation => {
                HttpResponse::INTERNAL_SERVER_ERROR.json("Token creation error")
            }
            AuthError::InvalidToken => HttpResponse::BAD_REQUEST.json("Invalid token"),
        }
    }
}
