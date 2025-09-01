use chrono::{Duration, Utc};
use mongodb::Database;
use mongodb::bson::oid::ObjectId;

use crate::core::extractors::AuthPayload;
use crate::scopes::auth::jwt::model::RefreshToken;
use crate::scopes::auth::model::PasswordResetTokens;
use crate::scopes::auth::tokens::JwtEncoderBuilder;
use crate::scopes::auth::{JWTService, PasswordResetTokenService};
use crate::scopes::user::service::UserService;

use super::error::{Error, Result};
use super::tokens::Tokens;
use super::user::User;

use super::utils::{AuthenticationHasher, Utils};

#[derive(Debug, Clone)]
pub struct AuthService {
    user_service: UserService,
    jwt_service: JWTService,
    password_reset_token_service: PasswordResetTokenService,
}
impl AuthService {
    pub fn new(db: &Database) -> Self {
        Self {
            user_service: UserService::new(db),
            jwt_service: JWTService::new(db),
            password_reset_token_service: PasswordResetTokenService::new(db),
        }
    }
}

// [ UserServiceTrait ]
pub trait UserServiceTrait {
    fn authenticate_user(
        &self,
        email: &str,
        password: &str,
    ) -> impl std::future::Future<Output = Result<User>> + Send;
    fn create_user(&self, user: User) -> impl std::future::Future<Output = Result<User>> + Send;
    fn find_user_by_email(
        &self,
        email: &str,
    ) -> impl std::future::Future<Output = Result<User>> + Send;
    fn find_user(&self, id: ObjectId) -> impl std::future::Future<Output = Result<User>> + Send;
    fn update_user_password(
        &self,
        id: ObjectId,
        hash: String,
    ) -> impl std::future::Future<Output = Result<User>> + Send;
    fn reset_password_state(
        &self,
        id: ObjectId,
    ) -> impl std::future::Future<Output = Result<User>> + Send;
}
impl UserServiceTrait for AuthService {
    async fn authenticate_user(&self, email: &str, password: &str) -> Result<User> {
        let user: User = self
            .user_service
            .find_by_email(email)
            .await
            .map_err(|_| Error::InvalidCredentials)?;
        match Utils::verify_password(password, &user.password) {
            true => Ok(user),
            false => {
                tracing::error!("Failed to verify password");
                Err(Error::InvalidCredentials)
            }
        }
    }
    async fn create_user(&self, user_data: User) -> Result<User> {
        user_data.validate()?;

        let password_hash = Utils::hash_password(&user_data.password)?;
        let mut user: User = User::from(user_data).with_password(password_hash);

        let user_id: ObjectId = self.user_service.insert(&user).await?;
        user.set_id(user_id);

        Ok(user)
    }
    async fn find_user_by_email(&self, email: &str) -> Result<User> {
        self.user_service.find_by_email(email).await
    }
    async fn find_user(&self, id: ObjectId) -> Result<User> {
        self.user_service.find(id).await
    }
    async fn update_user_password(&self, id: ObjectId, hash: String) -> Result<User> {
        self.user_service.update_password(id, hash).await
    }
    async fn reset_password_state(&self, id: ObjectId) -> Result<User> {
        self.user_service.reset_password_state(id).await
    }
}

// [ JwtServiceTrait ]
pub trait JwtServiceTrait {
    fn validate_jwt(
        &self,
        payload: AuthPayload,
        user_id: ObjectId,
    ) -> impl std::future::Future<Output = Result<()>> + Send;
    fn issue_and_save_tokens(
        &self,
        user: &User,
    ) -> impl std::future::Future<Output = Result<Tokens>> + Send;
    fn logout(&self, payload: AuthPayload) -> impl std::future::Future<Output = Result<()>> + Send;
    fn logout_all(&self, user_id: ObjectId)
    -> impl std::future::Future<Output = Result<()>> + Send;
}
impl JwtServiceTrait for AuthService {
    async fn validate_jwt(&self, payload: AuthPayload, user_id: ObjectId) -> Result<()> {
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

        Ok(())
    }
    async fn issue_and_save_tokens(&self, user: &User) -> Result<Tokens> {
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
    async fn logout(&self, payload: AuthPayload) -> Result<()> {
        self.jwt_service.invalidate(payload.jti).await?;
        Ok(())
    }
    async fn logout_all(&self, user_id: ObjectId) -> Result<()> {
        self.jwt_service.revoke(user_id).await?;
        Ok(())
    }
}

// [ PasswordResetTokenServiceTrait ]
pub trait PasswordResetTokenServiceTrait {
    fn validate_reset_password_token(
        &self,
        token: &str,
    ) -> impl std::future::Future<Output = Result<PasswordResetTokens>> + Send;
    fn process_reset_request(
        &self,
        user: User,
    ) -> impl std::future::Future<Output = Result<User>> + Send;

    fn invalidate_password_reset_token(
        &self,
        id: ObjectId,
    ) -> impl std::future::Future<Output = Result<PasswordResetTokens>> + Send;
    fn revoke_password_reset_token(
        &self,
        user_id: ObjectId,
    ) -> impl std::future::Future<Output = Result<()>> + Send;
    fn insert_password_reset_token(
        &self,
        otp: PasswordResetTokens,
    ) -> impl std::future::Future<Output = Result<()>> + Send;
}
impl PasswordResetTokenServiceTrait for AuthService {
    async fn validate_reset_password_token(&self, token: &str) -> Result<PasswordResetTokens> {
        let hash = Utils::hash_token(token);

        // 2. Checks the database for a matching token
        let reset_token = self.password_reset_token_service.find(hash).await?;

        // 3. Verify token isn't expired or already used
        if !reset_token.valid {
            return Err(Error::TokenAlreadyUsed);
        }
        if Utc::now() > reset_token.expired_at {
            let token_id = reset_token.id.unwrap_or_default();
            self.password_reset_token_service
                .invalidate(token_id)
                .await?;
            return Err(Error::TokenExpired);
        }

        Ok(reset_token)
    }

    async fn process_reset_request(&self, user: User) -> Result<User> {
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

    async fn invalidate_password_reset_token(&self, id: ObjectId) -> Result<PasswordResetTokens> {
        self.password_reset_token_service.invalidate(id).await
    }
    async fn revoke_password_reset_token(&self, user_id: ObjectId) -> Result<()> {
        self.password_reset_token_service.revoke(user_id).await
    }
    async fn insert_password_reset_token(&self, otp: PasswordResetTokens) -> Result<()> {
        self.password_reset_token_service.insert(otp).await
    }
}
