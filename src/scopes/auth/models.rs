use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use validator::Validate;

use crate::scopes::user::User;
use crate::services::jwt::Tokens;
use crate::utils::validation::validate_password;

use crate::config::PasswordRequirements;

#[derive(Debug, Deserialize, Validate, ToSchema)]
#[validate(context = "PasswordRequirements")]
#[schema(example = json!({"email": "example@email.com", "password": "password"}))]
pub struct LoginRequest {
    #[validate(email)]
    pub email: String,
    #[validate(custom(function = "validate_password", use_context))]
    pub password: String,
}
#[derive(Debug, Deserialize, Validate, ToSchema)]
#[validate(context = "PasswordRequirements")]
#[schema(example = json!({"username": "name", "email": "example@email.com", "password": "password"}))]
pub struct RegisterRequest {
    pub username: String,
    #[validate(email)]
    pub email: String,
    #[validate(custom(function = "validate_password", use_context))]
    pub password: String,
}

#[derive(Debug, Validate, Deserialize, ToSchema)]
#[schema(example = json!({"token": "edc365fa5e13751XXXXXXX"}))]
pub struct TokenQuery {
    // #[validate(custom(function = "validate_token"))]
    pub token: String,
}

#[derive(Debug, Validate, Deserialize, ToSchema)]
#[schema(example = json!({"email": "example@email.com"}))]
pub struct EmailRequest {
    #[validate(email)]
    pub email: String,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
#[schema(example = json!({"link": String::default(), "expires_at": "2026-02-19T22:42:23.467Z"}))]
pub struct ResetLink {
    pub link: String,
    pub expires_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Deserialize, Validate, ToSchema)]
#[validate(context = "PasswordRequirements")]
#[schema(example = json!({"token": String::default(), "csrf_token": String::default(), "password": String::default()}))]
pub struct ResetPasswordRequest {
    pub token: String,
    pub csrf_token: String,
    #[validate(custom(function = "validate_password", use_context))]
    pub password: String,
}

#[derive(Default, Debug, Serialize, Deserialize, ToSchema)]
#[schema(description = "SessionTokens model", example = json!({"access": String::default(), "refresh": String::default()}))]
pub struct SessionTokens {
    pub access: String,
    pub refresh: String,
}
#[derive(Default, Debug, Serialize, Deserialize, ToSchema)]
#[schema(description = "Verification model", example = json!({"token": String::default(), "link": String::default()}))]
pub struct Verification {
    token: String,
    link: String,
}
#[derive(Debug, Serialize, Deserialize, ToSchema)]
#[schema(example = json!({"user": User::default(), "tokens": Some(SessionTokens::default()), "verification": Some(Verification::default())}))]
pub struct AuthResponse {
    pub user: User,
    pub tokens: Option<SessionTokens>,
    pub verification: Option<Verification>,
}

impl AuthResponse {
    pub fn new(user: User) -> Self {
        Self {
            user,
            tokens: None,
            verification: None,
        }
    }
}

impl AuthResponse {
    pub fn with_jwt(mut self, tokens: Tokens) -> Self {
        let _ = self.tokens.insert(SessionTokens {
            access: tokens.access_token,
            refresh: tokens.refresh_token,
        });
        self
    }
    pub fn with_verification(mut self, link: &str, token: &str) -> Self {
        let _ = self.verification.insert(Verification {
            token: token.into(),
            link: link.into(),
        });
        self
    }
}
