use actix_web::{
    HttpResponse, ResponseError,
    http::{StatusCode, header::ContentType},
};
use derive_more::Display;
use serde_json::json;

pub type Result<T> = core::result::Result<T, Error>;

#[derive(Debug, Display)]
pub enum Error {
    #[display("User Creation Error")]
    UserCreationFailure,

    #[display("And error has occured while hashing")]
    HashingFailure,

    // Authentication & Authorization - 401/403
    #[display("Invalid credentials")]
    InvalidCredentials,

    #[display("Missing authentication credentials")]
    MissingCredentials,

    #[display("Invalid or expired token")]
    InvalidToken,

    #[display("Account has been suspended or blocked")]
    AccountSuspended,

    #[display("Rate Limit Exceeded")]
    RateLimitExceeded,

    // Not Found - 404
    #[display("User not found")]
    UserNotFound,

    #[display("Token not found")]
    TokenNotFound,

    // Bad Request - 400
    #[display("Invalid request format")]
    InvalidRequest,

    #[display("Token has expired")]
    TokenExpired,

    #[display("Token has already been used")]
    TokenAlreadyUsed,

    // Internal Server Error - 500
    #[display("Failed to create a token")]
    TokenCreationFailed,

    #[display("Database operation failed")]
    DatabaseError,

    #[display("Failed to send email")]
    EmailSendFailed,

    #[display("Failed to update password")]
    PasswordUpdateFailed,

    #[display("Failed to revoke tokens")]
    TokenRevocationFailed,

    #[display("Internal server error")]
    InternalServerError,
}

impl ResponseError for Error {
    fn error_response(&self) -> HttpResponse {
        HttpResponse::build(self.status_code())
            .insert_header(ContentType::json())
            .json(json!({"error": self.to_string()}))
    }

    fn status_code(&self) -> StatusCode {
        match self {
            Error::InvalidToken
            | Error::UserCreationFailure
            | Error::InvalidCredentials
            | Error::MissingCredentials => StatusCode::UNAUTHORIZED,

            Error::AccountSuspended | Error::RateLimitExceeded => StatusCode::FORBIDDEN,
            Error::UserNotFound | Error::TokenNotFound => StatusCode::NOT_FOUND,

            Error::InvalidRequest | Error::TokenExpired | Error::TokenAlreadyUsed => {
                StatusCode::BAD_REQUEST
            }

            Error::TokenCreationFailed
            | Error::HashingFailure
            | Error::DatabaseError
            | Error::EmailSendFailed
            | Error::PasswordUpdateFailed
            | Error::TokenRevocationFailed
            | Error::InternalServerError => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}
