use chrono::{Duration, Utc};
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
        let user: User = self
            .user_service
            .find_by_email(&req.email)
            .await
            .map_err(|_| Error::InvalidCredentials)?;

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
        user_data.validate()?;

        let password_hash = Utils::hash_password(&user_data.password)?;
        let mut user: User = User::from(user_data).with_password(password_hash);

        let user_id: ObjectId = self.user_service.insert(&user).await?;
        user.set_id(user_id);

        Ok(user)
    }

    #[tracing::instrument(name = "Create user", skip(payload))]
    pub async fn validate_token(&self, payload: AuthPayload) -> Result<User> {
        let user_id: ObjectId = ObjectId::parse_str(&payload.user_id).unwrap_or_default();

        // Use a middleware for this to check every req if account is active
        let user: User = self.user_service.find(user_id).await?;
        if user.account_locked {
            tracing::warn!("Blocked user attempted authentication: {}", user_id);
            return Err(Error::AccountSuspended);
        }

        if self.jwt_service.find(payload).await.is_none() {
            tracing::error!("Invalid refresh token detected for user: {}", user_id);

            // TODO: send an email
            // revoke or invalidate one token ?
            // maybe a user decided to revoke access to one of his devices
            // then he tried to use that devices, token is revoked but trying to validate it
            // will fail then self.jwt_service.revoke(user_id).await? will be excuted
            // [NOT RECOMMENDED]
            self.jwt_service.revoke(user_id).await?;
            return Err(Error::InvalidToken);
        }

        Ok(user)
    }

    #[tracing::instrument(name = "Issue authentication tokens", skip(user))]
    pub async fn issue_and_save_tokens(&self, user: &User) -> Result<Tokens> {
        let user_id: ObjectId = user.id.unwrap_or_default();

        let tokens: Tokens = JwtEncoderBuilder::default()
            .with_user_id(user_id.to_string())
            .build()
            .inspect_err(|e| {
                tracing::error!("Failed to generate authentication tokens: {:?}", e)
            })?;

        let hashed_refresh_token = Utils::hash_token(&tokens.refresh_token);

        let refresh_token = RefreshToken::default()
            .with_user_id(user_id)
            .with_hash(hashed_refresh_token)
            .with_jti(&tokens.refresh_token_jti)
            .with_issued_at(Utc::now())
            .with_expire_at(Utc::now() + Duration::days(30));

        self.jwt_service.insert(refresh_token).await?;
        Ok(tokens)
    }

    #[tracing::instrument(name = "Remove refreshToken", skip(payload))]
    pub async fn logout(&self, payload: AuthPayload) -> Result<()> {
        self.jwt_service.invalidate(payload.jti).await?;

        Ok(())
    }

    #[tracing::instrument(name = "Remove refreshToken", skip(user_id))]
    pub async fn logout_all(&self, user_id: ObjectId) -> Result<()> {
        self.jwt_service.revoke(user_id).await?;

        Ok(())
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
