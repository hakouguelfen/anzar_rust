use crate::config::PasswordConfig;
use crate::error::{CredentialField, Error, FailureReason, Result};
use crate::scopes::auth::service::AuthService;
use crate::scopes::email::model::EmailVerificationToken;
use crate::scopes::email::service::EmailVerificationTokenServiceTrait;
use crate::services::account::model::Account;
use crate::utils::{CustomPasswordHasher, Password, Token, TokenHasher};

use super::User;
use crate::scopes::auth::RegisterRequest;

pub trait UserServiceTrait {
    fn authenticate_user(&self, email: &str, password: &str) -> impl Future<Output = Result<bool>>;
    fn register_failed_attempt(
        &self,
        user: &str,
        device_cookie: Option<&str>,
        pass_config: &PasswordConfig,
    ) -> impl Future<Output = Result<u8>>;
    fn create_user(&self, req: RegisterRequest) -> impl Future<Output = Result<User>>;
    fn create_verification_email(
        &self,
        user: &User,
        expiray: i64,
    ) -> impl Future<Output = Result<String>>;
    fn find_user_by_email(&self, email: &str) -> impl Future<Output = Result<User>>;
    fn find_user(&self, id: &str) -> impl Future<Output = Result<User>>;
    fn update_user_password(&self, id: &str, hash: &str) -> impl Future<Output = Result<User>>;
    fn reset_password_state(&self, id: &str) -> impl Future<Output = Result<User>>;
    fn validate_account(&self, id: &str) -> impl Future<Output = Result<User>>;
    fn unlock_account(&self, id: &str) -> impl Future<Output = Result<User>>;
}
impl UserServiceTrait for AuthService {
    async fn authenticate_user(&self, email: &str, password: &str) -> Result<bool> {
        let user: User = self.user_service.find_by_email(email).await.map_err(|_| {
            Error::InvalidCredentials {
                field: CredentialField::Email,
                reason: FailureReason::NotFound,
            }
        })?;

        let user_id = user.id.as_ref().ok_or(Error::MalformedData {
            field: CredentialField::ObjectId,
        })?;
        let account = self.account_service.find(user_id).await?;

        Ok(Password::verify(password, &account.password))
    }

    async fn register_failed_attempt(
        &self,
        user: &str,
        device_cookie: Option<&str>,
        pass_config: &PasswordConfig,
    ) -> Result<u8> {
        let max_failed_attempts = match device_cookie {
            Some(_) => pass_config.security.max_failed_login_attempts * 2,
            None => pass_config.security.max_failed_login_attempts,
        };
        let key = match device_cookie {
            Some(val) => val.into(),
            None => format!("user:{}", user),
        };
        let attempts = self.user_service.increment(&key);

        // count number of failed authentication attempts within time period T for this specific cookie
        if attempts >= max_failed_attempts {
            self.user_service
                .put_cookie_in_lockout(&key, pass_config.security.lockout_duration as u32)?;
        }

        Ok(attempts)
    }
    async fn create_user(&self, req: RegisterRequest) -> Result<User> {
        let password = Password::hash(&req.password)?;
        let mut user = User::default()
            .with_username(&req.username)
            .with_email(&req.email);

        let user_id: String = self.user_service.insert(&user).await?;
        user.with_id(&user_id);

        // TODO: auto insert when user is created is available in mose DB
        let account = Account::user(&user_id).with_password(&password);
        self.account_service.insert(account).await?;

        Ok(user)
    }
    async fn create_verification_email(&self, user: &User, expiry: i64) -> Result<String> {
        let user_id = user.id.as_ref().ok_or(Error::MalformedData {
            field: CredentialField::ObjectId,
        })?;

        let token = Token::generate(32);
        let hashed_token = Token::hash(&token);

        let otp = EmailVerificationToken::default()
            .with_user_id(user_id)
            .with_token_hash(&hashed_token)
            .with_expiray(chrono::Duration::seconds(expiry));
        self.insert_email_verification_token(otp).await?;

        Ok(token)
    }

    async fn find_user_by_email(&self, email: &str) -> Result<User> {
        self.user_service.find_by_email(email).await
    }
    async fn find_user(&self, id: &str) -> Result<User> {
        self.user_service.find(id).await
    }
    async fn update_user_password(&self, id: &str, hash: &str) -> Result<User> {
        self.user_service.update_password(id, hash).await
    }
    async fn reset_password_state(&self, id: &str) -> Result<User> {
        self.user_service.reset_password_state(id).await
    }
    async fn unlock_account(&self, id: &str) -> Result<User> {
        self.user_service.unlock_account(id).await
    }
    async fn validate_account(&self, id: &str) -> Result<User> {
        self.user_service.validate_account(id).await
    }
}
