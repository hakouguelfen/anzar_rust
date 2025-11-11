use crate::config::{Configuration, PasswordConfig};
use crate::error::{CredentialField, Error, Result};
use crate::scopes::auth::service::AuthService;
use crate::scopes::email::model::EmailVerificationToken;
use crate::scopes::email::service::EmailVerificationTokenServiceTrait;
use crate::services::account::model::{Account, AccountStatus};
use crate::services::fake::service::FakeUserGenerator;
use crate::utils::{CustomPasswordHasher, DeviceCookie, Password, Token, TokenHasher};

use super::User;
use crate::scopes::auth::{RegisterRequest, support};

pub trait UserServiceTrait {
    fn find_by_email_with_password(
        &self,
        email: &str,
    ) -> impl Future<Output = Result<(User, String)>>;
    fn authenticate_user(
        &self,
        email: &str,
        password: &str,
        device_cookie: &DeviceCookie,
        session: &actix_session::Session,
        configuration: &Configuration,
    ) -> impl Future<Output = Result<(User, AccountStatus, u8)>>;
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
    fn validate_account(&self, id: &str) -> impl Future<Output = Result<User>>;
}
impl UserServiceTrait for AuthService {
    async fn find_by_email_with_password(&self, email: &str) -> Result<(User, String)> {
        // FIXME Single query with JOIN
        let user = self.user_service.find_by_email(email).await?;

        let id = user.id.as_ref().ok_or_else(|| Error::MalformedData {
            field: CredentialField::ObjectId,
        })?;

        let account = self.account_service.find(id).await?;

        Ok((user, account.password))
    }
    async fn authenticate_user(
        &self,
        email: &str,
        password: &str,
        device_cookie: &DeviceCookie,
        session: &actix_session::Session,
        configuration: &Configuration,
    ) -> Result<(User, AccountStatus, u8)> {
        let session_device_cookie = session.get::<String>("DeviceCookie").ok().flatten();
        let device_cookie_ref = session_device_cookie.as_deref();

        // ALWAYS execute ALL operations in parallel
        let (user_result, fake_data, suspension_check, attempts) = tokio::join!(
            self.find_by_email_with_password(email),
            async {
                FakeUserGenerator::new(configuration.security.secret_key.as_bytes())
                    .generate_fake_user_data(email)
            },
            async {
                let key = support::construct_key_from_device_cookie(session, device_cookie, email)
                    .unwrap();
                self.user_service.contains_key(&key)
            },
            self.register_failed_attempt(email, device_cookie_ref, &configuration.auth.password,)
        );

        // Select real or fake data (constant-time selection)
        let (target_user, target_hash) = match user_result {
            Ok((user, password_hash)) => (user.clone(), password_hash.clone()),
            Err(_) => (fake_data.0, fake_data.1),
        };
        // ALWAYS verify password (constant-time even with fake hash)
        let password_valid = Password::verify(password, &target_hash);

        let is_suspended = suspension_check;
        let is_unverified = configuration.auth.email.verification.required && !target_user.verified;

        let result = match password_valid {
            true if !is_suspended && !is_unverified => AccountStatus::Active,
            true if is_suspended => AccountStatus::Suspended,
            true if is_unverified => AccountStatus::Unverified,
            _ => AccountStatus::InvalidCredentials,
        };

        Ok((target_user.clone(), result, attempts.unwrap_or(0)))
    }

    async fn register_failed_attempt(
        &self,
        user: &str,
        device_cookie: Option<&str>,
        pass_config: &PasswordConfig,
    ) -> Result<u8> {
        let key = match device_cookie {
            Some(val) => val.into(),
            None => format!("user:{}", user),
        };
        if self.user_service.contains_key(&key) {
            return Ok(self.user_service.get_attempts(&key));
        }

        let attempts = self.user_service.increment(&key);

        // count number of failed authentication attempts within time period T for this specific cookie
        let max_failed_attempts = match device_cookie {
            Some(_) => pass_config.security.max_failed_login_attempts * 2,
            None => pass_config.security.max_failed_login_attempts,
        };
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
    async fn validate_account(&self, id: &str) -> Result<User> {
        self.user_service.validate_account(id).await
    }
}
