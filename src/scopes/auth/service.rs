use chrono::{Duration, Utc};

use crate::adapters::factory::DatabaseAdapters;
use crate::adapters::{mongodb::MongoDB, sqlite::SQLite};

use crate::config::DatabaseDriver;
use crate::error::{
    CredentialField, Error, FailureReason, InvalidTokenReason, Result, TokenErrorType,
};
use crate::extractors::AuthPayload;
use crate::scopes::auth::PasswordResetTokenService;
use crate::scopes::auth::model::PasswordResetToken;
use crate::scopes::user::service::UserService;

use crate::services::jwt::{JWTService, JwtEncoderBuilder, RefreshToken, Tokens};
use crate::utils::{AuthenticationHasher, Utils};

use super::user::User;

#[derive(Clone)]
pub struct AuthService {
    user_service: UserService,
    jwt_service: JWTService,
    password_reset_token_service: PasswordResetTokenService,
}

impl AuthService {
    pub async fn from_database(database_driver: DatabaseDriver, conn: String) -> Result<Self> {
        match database_driver {
            DatabaseDriver::SQLite => Ok(Self::from_sqlite(conn).await?),
            DatabaseDriver::MongoDB => Ok(Self::from_mongo(conn).await?),
            DatabaseDriver::PostgreSQL => todo!(),
        }
    }

    async fn from_sqlite(conn: String) -> Result<Self> {
        let driver = DatabaseDriver::SQLite;
        let db = SQLite::start(&conn).await?;

        // NOTE: this is for running testing only
        if &conn == "sqlite::memory:" {
            sqlx::migrate!("./migrations")
                .run(&db)
                .await
                .expect("migrations to run");
        }

        let adapters = DatabaseAdapters::sqlite(&db);

        Ok(Self {
            user_service: UserService::new(adapters.user_adapter, driver),
            jwt_service: JWTService::new(adapters.jwt_adapter, driver),
            password_reset_token_service: PasswordResetTokenService::new(
                adapters.reset_token_adapter,
                driver,
            ),
        })
    }

    async fn from_mongo(conn: String) -> Result<Self> {
        let driver = DatabaseDriver::MongoDB;
        let db = MongoDB::start(conn).await?;

        let adapters = DatabaseAdapters::mongodb(&db);

        Ok(Self {
            user_service: UserService::new(adapters.user_adapter, driver),
            jwt_service: JWTService::new(adapters.jwt_adapter, driver),
            password_reset_token_service: PasswordResetTokenService::new(
                adapters.reset_token_adapter,
                driver,
            ),
        })
    }
}

// [ UserServiceTrait ]
pub trait UserServiceTrait {
    fn authenticate_user(
        &self,
        email: &str,
        password: &str,
    ) -> impl std::future::Future<Output = Result<User>>;
    fn create_user(&self, user: User) -> impl std::future::Future<Output = Result<User>>;
    fn find_user_by_email(&self, email: &str) -> impl std::future::Future<Output = Result<User>>;
    fn find_user(&self, id: String) -> impl std::future::Future<Output = Result<User>>;
    fn update_user_password(
        &self,
        id: String,
        hash: String,
    ) -> impl std::future::Future<Output = Result<User>>;
    fn reset_password_state(&self, id: String) -> impl std::future::Future<Output = Result<User>>;
}
impl UserServiceTrait for AuthService {
    async fn authenticate_user(&self, email: &str, password: &str) -> Result<User> {
        let user: User = self.user_service.find_by_email(email).await.map_err(|_| {
            Error::InvalidCredentials {
                field: CredentialField::Email,
                reason: FailureReason::NotFound,
            }
        })?;

        match Utils::verify_password(password, &user.password) {
            true => Ok(user),
            false => {
                tracing::error!("Failed to verify password");
                Err(Error::InvalidCredentials {
                    field: CredentialField::Password,
                    reason: FailureReason::HashMismatch,
                })
            }
        }
    }
    async fn create_user(&self, user_data: User) -> Result<User> {
        user_data.validate()?;

        let password_hash = Utils::hash_password(&user_data.password)?;
        let mut user: User = User::from_request(user_data).with_password(password_hash);

        let user_id: String = self.user_service.insert(&user).await?;
        user.with_id(user_id);

        Ok(user)
    }
    async fn find_user_by_email(&self, email: &str) -> Result<User> {
        self.user_service.find_by_email(email).await
    }
    async fn find_user(&self, id: String) -> Result<User> {
        self.user_service.find(id).await
    }
    async fn update_user_password(&self, id: String, hash: String) -> Result<User> {
        self.user_service.update_password(id, hash).await
    }
    async fn reset_password_state(&self, id: String) -> Result<User> {
        self.user_service.reset_password_state(id).await
    }
}

// [ JwtServiceTrait ]
pub trait JwtServiceTrait {
    fn validate_jwt(
        &self,
        payload: AuthPayload,
        user_id: String,
    ) -> impl std::future::Future<Output = Result<()>>;
    fn issue_and_save_tokens(
        &self,
        user: &User,
    ) -> impl std::future::Future<Output = Result<Tokens>>;
    fn logout(&self, payload: AuthPayload) -> impl std::future::Future<Output = Result<()>>;
    fn logout_all(&self, user_id: String) -> impl std::future::Future<Output = Result<()>>;
    fn find_jwt_by_jti(&self, jti: &str)
    -> impl std::future::Future<Output = Option<RefreshToken>>;
}
impl JwtServiceTrait for AuthService {
    async fn validate_jwt(&self, payload: AuthPayload, user_id: String) -> Result<()> {
        if self.jwt_service.find(payload).await.is_none() {
            tracing::error!("Invalid refresh token detected for user: {}", user_id);

            // TODO: send an email
            // revoke or invalidate one token ?
            // maybe a user decided to revoke access to one of his devices
            // then he tried to use that devices, token is revoked but trying to validate it
            // will fail then self.jwt_service.revoke(user_id).await? will be excuted
            // [NOT RECOMMENDED]
            self.jwt_service.revoke(user_id).await?;
            return Err(Error::InvalidToken {
                token_type: TokenErrorType::RefreshToken,
                reason: InvalidTokenReason::NotFound,
            });
        }

        Ok(())
    }
    async fn issue_and_save_tokens(&self, user: &User) -> Result<Tokens> {
        let user_id = user.id.as_slice().concat();

        let tokens: Tokens = JwtEncoderBuilder::default()
            .with_user_id(&user_id)
            .build()
            .inspect_err(|e| {
                tracing::error!("Failed to generate authentication tokens: {:?}", e)
            })?;

        let hashed_refresh_token = Utils::hash_token(&tokens.refresh_token);

        let refresh_token = RefreshToken::default()
            .with_user_id(user_id.to_owned())
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
    async fn logout_all(&self, user_id: String) -> Result<()> {
        self.jwt_service.revoke(user_id).await?;
        Ok(())
    }

    async fn find_jwt_by_jti(&self, jti: &str) -> Option<RefreshToken> {
        self.jwt_service.find_by_jti(jti).await
    }
}

// [ PasswordResetTokenServiceTrait ]
pub trait PasswordResetTokenServiceTrait {
    fn validate_reset_password_token(
        &self,
        token: &str,
    ) -> impl std::future::Future<Output = Result<PasswordResetToken>>;
    fn process_reset_request(&self, user: User) -> impl std::future::Future<Output = Result<User>>;

    fn invalidate_password_reset_token(
        &self,
        id: String,
    ) -> impl std::future::Future<Output = Result<PasswordResetToken>>;
    fn revoke_password_reset_token(
        &self,
        user_id: String,
    ) -> impl std::future::Future<Output = Result<()>>;
    fn insert_password_reset_token(
        &self,
        otp: PasswordResetToken,
    ) -> impl std::future::Future<Output = Result<()>>;
}
impl PasswordResetTokenServiceTrait for AuthService {
    async fn validate_reset_password_token(&self, token: &str) -> Result<PasswordResetToken> {
        let hash = Utils::hash_token(token);

        // 2. Checks the database for a matching token
        let reset_token = self.password_reset_token_service.find(hash).await?;

        // 3. Verify token isn't expired or already used
        if !reset_token.valid {
            return Err(Error::TokenAlreadyUsed {
                token_id: reset_token.id.unwrap_or_default(),
            });
        }
        if Utc::now() > reset_token.expired_at {
            let token_id = reset_token.id.unwrap_or_default().to_string();
            self.password_reset_token_service
                .invalidate(token_id)
                .await?;
            return Err(Error::TokenExpired {
                token_type: TokenErrorType::PasswordResetToken,
                expired_at: reset_token.expired_at,
            });
        }

        Ok(reset_token)
    }

    async fn process_reset_request(&self, user: User) -> Result<User> {
        let user_id = user.id.unwrap_or_default();

        let window_expired = user
            .password_reset_window_start
            .is_none_or(|start| Utc::now() - start > Duration::hours(1));

        if window_expired {
            self.user_service
                .update_reset_window(user_id.to_string())
                .await?;
        }

        let user = self
            .user_service
            .increment_reset_count(user_id.to_string())
            .await?;
        Ok(user)
    }

    async fn invalidate_password_reset_token(&self, id: String) -> Result<PasswordResetToken> {
        self.password_reset_token_service.invalidate(id).await
    }
    async fn revoke_password_reset_token(&self, user_id: String) -> Result<()> {
        self.password_reset_token_service.revoke(user_id).await
    }
    async fn insert_password_reset_token(&self, otp: PasswordResetToken) -> Result<()> {
        self.password_reset_token_service.insert(otp).await
    }
}
