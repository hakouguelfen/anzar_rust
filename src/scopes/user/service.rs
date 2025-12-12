use crate::config::{Configuration, PasswordConfig};
use crate::error::{CredentialField, Error, Result};
use crate::scopes::auth::service::AuthService;
use crate::scopes::email::model::EmailVerificationToken;
use crate::scopes::email::service::EmailVerificationTokenServiceTrait;
use crate::services::account::model::{Account, AccountStatus};
use crate::services::fake::service::FakeUserGenerator;
use crate::services::lockout::service::LockoutService;
use crate::utils::{CustomPasswordHasher, HmacSigner, Password, Token, TokenHasher};

use super::User;
use crate::scopes::auth::{RegisterRequest, support};

pub trait UserServiceTrait {
    fn find_by_email_with_password(
        &self,
        email: &str,
        configuration: &Configuration,
    ) -> impl Future<Output = Result<(User, String)>>;
    fn authenticate_user(
        &self,
        email: &str,
        password: &str,
        device_cookie: &HmacSigner,
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
    async fn find_by_email_with_password(
        &self,
        email: &str,
        configuration: &Configuration,
    ) -> Result<(User, String)> {
        // FIXME Single query with JOIN
        // Try to fetch real user
        let real = self.user_service.find_by_email(email).await.ok();

        // Extract real password hash or use a fake one
        let (user, password) = match real {
            Some(user) => {
                match self
                    .account_service
                    .find(&user.clone().id.unwrap_or_default())
                    .await
                {
                    Ok(account) => (user, account.password),
                    Err(_) => {
                        let fake_gen = FakeUserGenerator::new(&configuration.security.secret_key);
                        (
                            fake_gen.generate_fake_user(email),
                            fake_gen.generate_fake_hash(),
                        )
                    }
                }
            }
            None => {
                let fake_gen = FakeUserGenerator::new(&configuration.security.secret_key);
                (
                    fake_gen.generate_fake_user(email),
                    fake_gen.generate_fake_hash(),
                )
            }
        };

        Ok((user, password))
    }
    async fn authenticate_user(
        &self,
        email: &str,
        password: &str,
        hmac_signer: &HmacSigner,
        session: &actix_session::Session,
        configuration: &Configuration,
    ) -> Result<(User, AccountStatus, u8)> {
        let raw = session.get::<String>(support::DEVICE_COOKIE).ok().flatten();
        let device_cookie = raw.as_deref();

        let lockout_service = LockoutService::new(hmac_signer);

        // ALWAYS verify password (constant-time even with fake hash)
        let (target_user, target_hash) = self
            .find_by_email_with_password(email, configuration)
            .await?;
        let password_valid = Password::verify(password, &target_hash);

        let lockout_key = lockout_service.lockout_key(device_cookie, email);
        let is_suspended = self.user_service.contains_key(&lockout_key);

        let is_unverified = configuration.auth.email.verification.required && !target_user.verified;

        let account_status = match password_valid {
            true if !is_suspended && !is_unverified => AccountStatus::Active,
            true if is_suspended => AccountStatus::Suspended,
            true if is_unverified => AccountStatus::Unverified,
            _ => AccountStatus::InvalidCredentials,
        };

        let attempts_key = lockout_service.attempts_key(device_cookie, email);
        let attempts = if account_status == AccountStatus::Active {
            self.user_service.clear_key(&attempts_key);
            0
        } else {
            self.register_failed_attempt(email, device_cookie, &configuration.auth.password)
                .await
                .unwrap_or(0)
        };

        Ok((target_user.clone(), account_status, attempts))
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
        /* FIXME Make sure if a failure accure to return an error
                 sometimes even though transaction have failed, no data is saved
                 the function return a success 200 code.
        */
        let mut session = self.transaction_repository.start_transactions().await?;

        let password = Password::hash(&req.password)?;
        let mut user = User::default()
            .with_username(&req.username)
            .with_email(&req.email);

        let user_id: String = self.user_service.insert(&user, Some(&mut session)).await?;
        user.with_id(&user_id);

        let account = Account::user(&user_id).with_password(&password);
        self.account_service
            .insert(account, Some(&mut session))
            .await?;

        self.transaction_repository
            .commit_transaction(session)
            .await?;

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
