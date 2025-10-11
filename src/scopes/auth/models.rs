use serde::{Deserialize, Serialize};
use validator::Validate;

// use crate::utils::validation::validate_token;
use crate::{scopes::user::UserResponse, services::jwt::Tokens};

#[derive(Debug, Deserialize, Validate)]
pub struct LoginRequest {
    #[validate(email)]
    pub email: String,
    #[validate(length(min = 8, message = "password must be at least 8 characters"))]
    pub password: String,
}

#[derive(Debug, Validate, Deserialize)]
pub struct TokenQuery {
    // #[validate(custom(function = "validate_token"))]
    pub token: String,
}

#[derive(Debug, Validate, Deserialize)]
pub struct EmailRequest {
    #[validate(email)]
    pub email: String,
}

#[derive(Debug, Deserialize)]
pub struct ResetPasswordRequest {
    // #[validate(custom(function = "validate_token"))]
    pub token: String,
    // #[validate(length(min = 8, message = "password must be at least 8 characters"))]
    pub password: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthResponse {
    #[serde(rename = "accessToken")]
    pub access_token: String,
    #[serde(rename = "refreshToken")]
    pub refresh_token: String,
    pub user: UserResponse,
}
impl AuthResponse {
    pub fn with_jwt(tokens: Tokens, user_response: UserResponse) -> Self {
        Self {
            access_token: tokens.access_token,
            refresh_token: tokens.refresh_token,
            user: user_response,
        }
    }
}
