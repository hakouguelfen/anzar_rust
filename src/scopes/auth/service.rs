use chrono::{Duration, Local, Utc};
use mongodb::Database;
use mongodb::bson::oid::ObjectId;

use crate::scopes::auth::jwt::service::JWTService;
use crate::scopes::user::service::UserService;

use super::error::{Error, Result};
use super::jwt::model::RefreshToken;
use super::models::{AuthPayload, LoginRequest};
use super::tokens::{JwtEncoderBuilder, Tokens};
use super::user::User;

use super::utils::{AuthenticationHasher, Utils};

#[derive(Debug)]
pub struct AuthService {
    user_service: UserService,
    jwt_service: JWTService,
}

impl AuthService {
    pub fn new(db: &Database) -> Self {
        Self {
            user_service: UserService::new(db),
            jwt_service: JWTService::new(db),
        }
    }

    #[tracing::instrument(name = "Check user credentials", skip(req))]
    pub async fn check_credentials(&self, req: LoginRequest) -> Result<User> {
        let user: User = self.user_service.find_by_email(&req.email).await?;

        match Utils::verify_password(&req.password, &user.password) {
            true => Ok(user),
            false => {
                tracing::error!("Failed to verify password");
                Err(Error::InvalidCredentials)
            }
        }
    }

    #[tracing::instrument(name = "Create user", skip(user_data))]
    pub async fn create_user(&self, user_data: User) -> Result<User> {
        let password_hash = Utils::hash_password(&user_data.password)?;
        let mut user: User = User::new(user_data).with_password(password_hash);

        let user_id: ObjectId = self.user_service.insert(&user).await?;
        user.with_id(user_id);

        Ok(user)
    }

    #[tracing::instrument(name = "Create user", skip(payload))]
    pub async fn validate_token(&self, payload: AuthPayload) -> Result<User> {
        if payload.user_id.is_empty() || payload.refresh_token.is_empty() {
            tracing::error!(
                "Failed to regenerate accessToken because (user_id | refresh_token) is empty"
            );
            return Err(Error::MissingCredentials);
        }

        let user_id: ObjectId = ObjectId::parse_str(&payload.user_id).map_err(|e| {
            tracing::error!("Failed to parse user_id to ObjectId: {:?}", e);
            Error::InvalidCredentials
        })?;

        let user: User = self.user_service.find(user_id).await?;

        // 4. Check if user account is active
        if user.account_locked {
            tracing::warn!("Blocked user attempted authentication: {}", user_id);
            return Err(Error::AccountSuspended);
        }

        let refresh_token: RefreshToken = self
            .jwt_service
            .find(user_id, &payload.refresh_token)
            .await?;

        if !refresh_token.valid {
            tracing::error!(
                "Invalid refresh token detected for user: {} - revoking all tokens",
                user_id
            );
            // Security: revoke all tokens for this user
            self.jwt_service.revoke(user_id).await?;
            return Err(Error::InvalidToken);
        }

        // if refresh token is valid, invalidated then issue a new pair of tokens
        let token_id = refresh_token.id.unwrap_or_default();
        self.jwt_service.invalidate(token_id).await?;

        Ok(user)
    }

    #[tracing::instrument(name = "Issue authentication tokens", skip(user))]
    pub async fn issue_and_save_tokens(&self, user: &User) -> Result<Tokens> {
        let user_id: ObjectId = user.id.unwrap_or_default();

        let tokens: Tokens = JwtEncoderBuilder::default()
            .with_user_id(user_id.to_string())
            .with_role(user.role.clone())
            .build()
            .inspect_err(|e| {
                tracing::error!("Failed to generate authentication tokens: {:?}", e)
            })?;

        let hashed_refresh_token = Utils::hash_token(&tokens.refresh_token);

        let refresh_token = RefreshToken::default()
            .with_user_id(user_id)
            .with_hash(hashed_refresh_token)
            .with_issued_at(Local::now().timestamp() as usize)
            .with_expire_at((Local::now() + Duration::days(30)).timestamp() as usize);

        self.jwt_service.insert(refresh_token).await?;

        Ok(tokens)
    }

    #[tracing::instrument(name = "Remove refreshToken", skip(user_id))]
    pub async fn logout(&self, user_id: ObjectId) -> Result<User> {
        let user = self.user_service.clear_token(user_id).await?;
        self.jwt_service.revoke(user_id).await?;

        Ok(user)
    }

    #[tracing::instrument(name = "Forgot password", skip(user))]
    pub async fn process_reset_request(&self, user: User) -> Result<User> {
        let user_id = user.id.unwrap_or_default();

        let window_expired = user
            .password_reset_window_start
            .is_none_or(|start| Utc::now() - start > Duration::hours(1));

        if window_expired {
            self.user_service.update_reset_window(user_id).await?;
        }

        let user = self.user_service.increment_reset_count(user_id).await?;
        Ok(user)
    }
}
