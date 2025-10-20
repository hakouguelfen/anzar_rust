use actix_session::{SessionGetError, SessionInsertError};
use actix_web::{HttpResponse, http::StatusCode};
use chrono::{DateTime, Duration, Utc};
use derive_more::From;
use serde::Serialize;

pub type Result<T> = core::result::Result<T, Error>;

#[derive(Debug)]
pub enum FailureReason {
    NotFound,
    AlreadyExist,
    Expired,
    Empty,
    Malformed,
    HashMismatch,
    UnauthorizedSource,
}
#[derive(Debug)]
pub enum InvalidTokenReason {
    Malformed,
    SignatureMismatch,
    Expired,
    NotFound,
}
#[derive(Debug)]
pub enum CredentialField {
    Username,
    Email,
    Password,
    Token,
    ApiKey,
    ObjectId,
}
#[derive(Debug)]
pub enum TokenErrorType {
    Token,
    AccessToken,
    RefreshToken,
    SessionToken,
    PasswordResetToken,
    EmailVerificationToken,
}

impl From<Error> for std::io::Error {
    fn from(err: Error) -> Self {
        std::io::Error::other(err.to_string())
    }
}

#[derive(Debug, From)]
pub enum Error {
    // -- Tokens
    InvalidToken {
        token_type: TokenErrorType,
        reason: InvalidTokenReason,
    },
    TokenNotFound {
        token_id: String,
    },
    TokenExpired {
        token_type: TokenErrorType,
        expired_at: DateTime<Utc>,
    },
    TokenAlreadyUsed {
        token_id: String,
    },
    TokenCreationFailed {
        token_type: TokenErrorType,
    },
    TokenRevocationFailed {
        token_id: String,
    },

    // -- Accounts
    AccuontNotVerified {
        field: CredentialField,
    },
    InvalidCredentials {
        field: CredentialField,
        reason: FailureReason,
    },
    MissingCredentials {
        field: CredentialField,
    },
    AccountSuspended {
        user_id: String,
    },
    UserNotFound {
        user_id: Option<String>,
        email: Option<String>,
    },

    // -- Rate Limiting
    RateLimitExceeded {
        limit: u32,
        window: Duration,
    },

    // --Communication
    EmailSendFailed {
        to: String,
    },
    TlsConfig {
        path: String,
        reason: FailureReason,
    },

    HashingFailure,
    MalformedData {
        field: CredentialField,
    },
    DatabaseError(String),
    InvalidRequest,

    BadRequest(String),
    InternalServerError(String),

    // -- Externals
    #[from]
    Actix(actix_web::Error),
    #[from]
    IO(std::io::Error),
    #[from]
    SerdeYaml(serde_yaml::Error),
    #[from]
    SessionInsert(SessionInsertError),
    #[from]
    SessionGet(SessionGetError),
    #[from]
    JWT(jsonwebtoken::errors::Error),
    #[from]
    Validation(validator::ValidationError),
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(f, "{self:?}")
    }
}

#[derive(Serialize)]
struct ErrorResponse {
    message: String,
}
impl actix_web::ResponseError for Error {
    fn error_response(&self) -> actix_web::HttpResponse {
        let status_code = self.status_code();
        let error_response = ErrorResponse {
            message: self.to_string(),
        };

        HttpResponse::build(status_code).json(error_response)
    }

    fn status_code(&self) -> StatusCode {
        match self {
            Error::InvalidToken {
                token_type: _,
                reason: _,
            }
            | Error::AccuontNotVerified { field: _ }
            | Error::InvalidCredentials {
                field: _,
                reason: _,
            }
            | Error::MissingCredentials { field: _ } => StatusCode::UNAUTHORIZED,

            Error::AccountSuspended { user_id: _ } => StatusCode::FORBIDDEN,

            Error::RateLimitExceeded {
                limit: _,
                window: _,
            } => StatusCode::TOO_MANY_REQUESTS,

            Error::UserNotFound {
                user_id: _,
                email: _,
            }
            | Error::TokenNotFound { token_id: _ } => StatusCode::NOT_FOUND,

            Error::BadRequest(_)
            | Error::InvalidRequest
            | Error::TokenExpired {
                token_type: _,
                expired_at: _,
            }
            | Error::MalformedData { field: _ }
            | Error::TokenAlreadyUsed { token_id: _ }
            | Error::Validation(_) => StatusCode::BAD_REQUEST,

            Error::TokenCreationFailed { token_type: _ }
            | Error::HashingFailure
            | Error::DatabaseError(_)
            | Error::EmailSendFailed { to: _ }
            | Error::TokenRevocationFailed { token_id: _ }
            | Error::TlsConfig { path: _, reason: _ }
            | Error::InternalServerError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Error::Actix(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Error::IO(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Error::SerdeYaml(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Error::JWT(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Error::SessionInsert(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Error::SessionGet(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}
