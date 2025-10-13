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
use crate::scopes::config::Database;
use crate::scopes::user::service::UserService;

use crate::services::jwt::{JWTService, JwtEncoderBuilder, RefreshToken, Tokens};
use crate::services::session::{model::Session, service::SessionService};
use crate::utils::{CustomPasswordHasher, Password, Token, TokenHasher};

use super::user::User;

#[derive(Clone)]
pub struct AuthService {
    user_service: UserService,
    jwt_service: JWTService,
    session_service: SessionService,
    password_reset_token_service: PasswordResetTokenService,
}

impl AuthService {
    pub fn new(adapters: DatabaseAdapters, driver: DatabaseDriver) -> Self {
        Self {
            user_service: UserService::new(adapters.user_adapter, driver),
            jwt_service: JWTService::new(adapters.jwt_adapter, driver),
            session_service: SessionService::new(adapters.session_adapter, driver),
            password_reset_token_service: PasswordResetTokenService::new(
                adapters.reset_token_adapter,
                driver,
            ),
        }
    }
    pub async fn from_database(database: &Database) -> Result<Self> {
        match database.driver {
            // DatabaseDriver::SQLite => Ok(Self::from_sqlite("/app/test.db".into()).await?),
            DatabaseDriver::SQLite => Ok(Self::from_sqlite(&database.connection_string).await?),
            DatabaseDriver::MongoDB => Ok(Self::from_mongo(&database.connection_string).await?),
            DatabaseDriver::PostgreSQL => todo!(),
        }
    }

    async fn from_sqlite(conn: &str) -> Result<Self> {
        let db = SQLite::start(conn).await?;
        let adapters = DatabaseAdapters::sqlite(&db);

        Ok(Self::new(adapters, DatabaseDriver::SQLite))
    }

    async fn from_mongo(conn: &str) -> Result<Self> {
        let db = MongoDB::start(conn).await?;
        let adapters = DatabaseAdapters::mongodb(&db);

        Ok(Self::new(adapters, DatabaseDriver::MongoDB))
    }
}

// [ UserServiceTrait ]
pub trait UserServiceTrait {
    fn authenticate_user(&self, email: &str, password: &str) -> impl Future<Output = Result<User>>;
    fn create_user(&self, user: User) -> impl Future<Output = Result<User>>;
    fn find_user_by_email(&self, email: &str) -> impl Future<Output = Result<User>>;
    fn find_user(&self, id: &str) -> impl Future<Output = Result<User>>;
    fn update_user_password(&self, id: &str, hash: &str) -> impl Future<Output = Result<User>>;
    fn reset_password_state(&self, id: &str) -> impl Future<Output = Result<User>>;
}
impl UserServiceTrait for AuthService {
    async fn authenticate_user(&self, email: &str, password: &str) -> Result<User> {
        let user: User = self.user_service.find_by_email(email).await.map_err(|_| {
            Error::InvalidCredentials {
                field: CredentialField::Email,
                reason: FailureReason::NotFound,
            }
        })?;

        match Password::verify(password, &user.password) {
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
    async fn create_user(&self, user: User) -> Result<User> {
        user.validate()?;

        let password_hash = Password::hash(&user.password)?;
        let mut user = user.with_password(password_hash);

        let user_id: String = self.user_service.insert(&user).await?;
        user.with_id(user_id);

        Ok(user)
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
}

// [ JwtServiceTrait ]
pub trait JwtServiceTrait {
    fn validate_jwt(&self, payload: AuthPayload, user_id: &str)
    -> impl Future<Output = Result<()>>;
    fn issue_and_save_tokens(
        &self,
        user: &User,
    ) -> impl std::future::Future<Output = Result<Tokens>>;
    fn invalidate_jwt(&self, jti: &str) -> impl Future<Output = Result<()>>;
    fn invalidate_session(&self, session_id: &str) -> impl Future<Output = Result<()>>;
    fn logout(&self, payload: AuthPayload) -> impl Future<Output = Result<()>>;
    fn logout_all(&self, user_id: &str) -> impl Future<Output = Result<()>>;
    fn find_jwt_by_jti(&self, jti: &str) -> impl Future<Output = Result<RefreshToken>>;
}
impl JwtServiceTrait for AuthService {
    async fn validate_jwt(&self, payload: AuthPayload, user_id: &str) -> Result<()> {
        if self.jwt_service.find(payload).await.is_none() {
            tracing::error!("Invalid refresh token detected for user: {}", user_id);

            // TODO: send an email indicating a breach
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
        let user_id = user.id.as_ref().ok_or(Error::MalformedData {
            field: CredentialField::ObjectId,
        })?;

        let tokens: Tokens = JwtEncoderBuilder::new(user_id).build().inspect_err(|e| {
            tracing::error!("Failed to generate authentication tokens: {:?}", e)
        })?;

        let hashed_refresh_token = Token::hash(&tokens.refresh_token);

        let refresh_token = RefreshToken::default()
            .with_user_id(user_id)
            .with_hash(&hashed_refresh_token)
            .with_jti(&tokens.refresh_token_jti)
            .with_issued_at(Utc::now())
            .with_expire_at(Utc::now() + Duration::days(30));

        self.jwt_service.insert(refresh_token).await?;

        Ok(tokens)
    }

    async fn invalidate_jwt(&self, jti: &str) -> Result<()> {
        self.jwt_service.invalidate(jti).await?;
        Ok(())
    }
    async fn invalidate_session(&self, token: &str) -> Result<()> {
        self.session_service.invalidate(token).await?;
        Ok(())
    }

    async fn logout(&self, payload: AuthPayload) -> Result<()> {
        self.jwt_service.invalidate(&payload.jti).await?;
        self.session_service.revoke(&payload.user_id).await?;
        Ok(())
    }
    async fn logout_all(&self, user_id: &str) -> Result<()> {
        self.jwt_service.revoke(user_id).await?;
        self.session_service.revoke(user_id).await?;
        Ok(())
    }

    async fn find_jwt_by_jti(&self, jti: &str) -> Result<RefreshToken> {
        self.jwt_service.find_by_jti(jti).await
    }
}

// [ PasswordResetTokenServiceTrait ]
pub trait PasswordResetTokenServiceTrait {
    fn validate_reset_password_token(
        &self,
        token: &str,
    ) -> impl Future<Output = Result<PasswordResetToken>>;
    fn increment_reset_attempts(&self, user: User) -> impl Future<Output = Result<User>>;

    fn invalidate_password_reset_token(
        &self,
        id: &str,
    ) -> impl Future<Output = Result<PasswordResetToken>>;
    fn revoke_password_reset_token(
        &self,
        user_id: &str,
    ) -> impl std::future::Future<Output = Result<()>>;
    fn insert_password_reset_token(
        &self,
        otp: PasswordResetToken,
    ) -> impl Future<Output = Result<()>>;
}
impl PasswordResetTokenServiceTrait for AuthService {
    async fn validate_reset_password_token(&self, token: &str) -> Result<PasswordResetToken> {
        let hash = Token::hash(token);

        // 2. Checks the database for a matching token
        let reset_token = self.password_reset_token_service.find(&hash).await?;
        let reset_token_id = reset_token.id.as_ref().ok_or(Error::MalformedData {
            field: CredentialField::ObjectId,
        })?;

        // 3. Verify token isn't expired or already used
        if !reset_token.valid {
            return Err(Error::TokenAlreadyUsed {
                token_id: reset_token_id.into(),
            });
        }
        if Utc::now() > reset_token.expired_at {
            self.password_reset_token_service
                .invalidate(reset_token_id)
                .await?;
            return Err(Error::TokenExpired {
                token_type: TokenErrorType::PasswordResetToken,
                expired_at: reset_token.expired_at,
            });
        }

        Ok(reset_token)
    }

    async fn increment_reset_attempts(&self, user: User) -> Result<User> {
        let user_id = user.id.as_ref().ok_or(Error::MalformedData {
            field: CredentialField::ObjectId,
        })?;

        let window_expired = user
            .password_reset_window_start
            .is_none_or(|start| Utc::now() - start > Duration::hours(1));

        if window_expired {
            self.user_service.update_reset_window(user_id).await?;
        }

        let user = self.user_service.increment_reset_count(user_id).await?;
        Ok(user)
    }

    async fn invalidate_password_reset_token(&self, id: &str) -> Result<PasswordResetToken> {
        self.password_reset_token_service.invalidate(id).await
    }
    async fn revoke_password_reset_token(&self, user_id: &str) -> Result<()> {
        self.password_reset_token_service.revoke(user_id).await
    }
    async fn insert_password_reset_token(&self, otp: PasswordResetToken) -> Result<()> {
        self.password_reset_token_service.insert(otp).await
    }
}

// [ SessionTrait ]
pub trait SessionServiceTrait {
    fn issue_session(&self, user_id: &User) -> impl Future<Output = Result<String>>;
    fn find_session(&self, session_id: &str) -> impl Future<Output = Result<Session>>;
    fn extend_timeout(&self, session_id: &str) -> impl Future<Output = Result<Session>>;
}
impl SessionServiceTrait for AuthService {
    async fn issue_session(&self, user: &User) -> Result<String> {
        let user_id = user.id.as_ref().ok_or(Error::MalformedData {
            field: CredentialField::ObjectId,
        })?;

        self.session_service.revoke(user_id).await?;

        let token = Token::generate(32);
        let hashed_token = Token::hash(&token);

        let session = Session::default()
            .with_user_id(user_id)
            .with_token(&hashed_token);
        self.session_service.insert(session).await?;

        Ok(token)
    }
    async fn find_session(&self, session_id: &str) -> Result<Session> {
        self.session_service.find(session_id).await
    }
    async fn extend_timeout(&self, session_id: &str) -> Result<Session> {
        self.session_service.extend_timeout(session_id).await
    }
}
