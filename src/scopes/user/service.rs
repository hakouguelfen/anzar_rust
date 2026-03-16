use crate::config::{Configuration, PasswordConfig};
use crate::error::{CredentialField, Error, Result};
use crate::scopes::auth::service::AuthService;
use crate::scopes::email::model::EmailVerificationToken;
use crate::scopes::email::service::EmailVerificationTokenServiceTrait;
use crate::services::account::model::{Account, AccountStatus};
use crate::services::fake::service::FakeUserGenerator;
use crate::services::lockout::service::LoginAttemptTracker;
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
        // 1. ALWAYS verify password (constant-time even with fake hash)
        let (target_user, target_hash) = self
            .find_by_email_with_password(email, configuration)
            .await?;
        let password_valid = Password::verify(password, &target_hash);

        // 2. Fetch device cookie
        let raw = session.get::<String>(support::DEVICE_COOKIE).ok().flatten();
        let device_cookie = raw.as_deref();

        // 3.
        let tracker = LoginAttemptTracker::new(hmac_signer);
        let identity = tracker.resolve_identity(device_cookie, email);
        let lockout_key = tracker.resolve_lockout_key(device_cookie, email);

        // FIXME
        // 4. Use cache_service instead of user_service (more readable)
        if self.user_service.is_locked(&lockout_key) {
            self.user_service.reset_attempts(&identity);
            return Ok((target_user.clone(), AccountStatus::Suspended, 0));
        }

        // 5.
        match password_valid {
            true => {
                self.user_service.clear_key(&identity);
                Ok((target_user.clone(), AccountStatus::Active, 0))
            }
            _ => {
                let attempts = self
                    .register_failed_attempt(&identity, device_cookie, &configuration.auth.password)
                    .await
                    .unwrap_or(1);
                Ok((
                    target_user.clone(),
                    AccountStatus::InvalidCredentials,
                    attempts,
                ))
            }
        }
    }

    async fn register_failed_attempt(
        &self,
        identity: &str,
        device_cookie: Option<&str>,
        pass_config: &PasswordConfig,
    ) -> Result<u8> {
        let attempts = self.user_service.increment(identity);

        // max_failed_attempts of authentication within for this specific cookie
        let max_failed_attempts = match device_cookie {
            Some(_) => pass_config.security.max_failed_login_attempts * 2,
            None => pass_config.security.max_failed_login_attempts,
        };
        if attempts >= max_failed_attempts {
            self.user_service
                .put_cookie_in_lockout(identity, pass_config.security.lockout_duration as u32)?;
        }

        Ok(attempts)
    }

    async fn create_user(&self, req: RegisterRequest) -> Result<User> {
        /* FIXME Make sure if a failure happen, return an error
                 sometimes even though transaction have failed, no data is saved
                 the function return a success 200 code.
        */
        // let mut session = self.transaction_repository.start_transactions().await?;

        let password = Password::hash(&req.password)?;
        let mut user = User::new()
            .with_username(&req.username)
            .with_email(&req.email);

        // let user_id: String = self.user_service.insert(&user, Some(&mut session)).await?;
        let user_id: String = self.user_service.insert(&user, None).await?;
        user.with_id(&user_id);

        let account = Account::user(&user_id).with_password(&password);
        self.account_service.insert(account, None).await?;

        // self.transaction_repository
        //     .commit_transaction(session)
        //     .await?;

        Ok(user)
    }
    async fn create_verification_email(&self, user: &User, expiry: i64) -> Result<String> {
        let user_id = user.id.as_ref().ok_or(Error::MalformedData {
            field: CredentialField::ObjectId,
        })?;

        let token = Token::with_size32().generate();
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
