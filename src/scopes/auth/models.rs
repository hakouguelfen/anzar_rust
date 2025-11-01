use serde::{Deserialize, Serialize};
use validator::Validate;

use crate::scopes::user::User;
use crate::services::jwt::Tokens;
use crate::utils::validation::validate_password;

use crate::config::PasswordRequirements;

#[derive(Debug, Deserialize, Validate)]
#[validate(context = "PasswordRequirements")]
pub struct LoginRequest {
    #[validate(email)]
    pub email: String,
    #[validate(custom(function = "validate_password", use_context))]
    pub password: String,
}
#[derive(Debug, Deserialize, Validate)]
#[validate(context = "PasswordRequirements")]
pub struct RegisterRequest {
    pub username: String,
    #[validate(email)]
    pub email: String,
    #[validate(custom(function = "validate_password", use_context))]
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

#[derive(Debug, Serialize, Deserialize)]
pub struct ResetLink {
    pub link: String,
    pub expires_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Deserialize, Validate)]
#[validate(context = "PasswordRequirements")]
pub struct ResetPasswordRequest {
    pub token: String,
    pub csrf_token: String,
    #[validate(custom(function = "validate_password", use_context))]
    pub password: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SessionTokens {
    pub access: String,
    pub refresh: String,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct Verification {
    token: String,
    link: String,
}
#[derive(Debug, Serialize, Deserialize)]
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
