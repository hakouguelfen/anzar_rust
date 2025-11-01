use crate::adapters::factory::DatabaseAdapters;
use crate::adapters::memcache::{MemCache, MemCacheAdapter};
use crate::adapters::{mongodb::MongoDB, sqlite::SQLite};

use crate::config::{Database, DatabaseDriver};
use crate::error::Result;

use crate::scopes::auth::PasswordResetTokenRepository;
use crate::scopes::email::EmailVerificationTokenRepository;
use crate::scopes::user::UserRepository;
use crate::services::account::AccountRepository;
use crate::services::jwt::JWTRepository;
use crate::services::session::SessionRepository;

#[derive(Clone)]
pub struct AuthService {
    pub(crate) user_service: UserRepository,
    pub(crate) account_service: AccountRepository,
    pub(crate) jwt_service: JWTRepository,
    pub(crate) session_service: SessionRepository,
    pub(crate) password_reset_token_service: PasswordResetTokenRepository,
    pub(crate) email_verification_token_service: EmailVerificationTokenRepository,
}

impl AuthService {
    pub fn new(
        adapters: DatabaseAdapters,
        driver: DatabaseDriver,
        memcache: MemCacheAdapter,
    ) -> Self {
        Self {
            user_service: UserRepository::new(adapters.user_adapter, driver, memcache),
            account_service: AccountRepository::new(adapters.account_adapter, driver),
            jwt_service: JWTRepository::new(adapters.jwt_adapter, driver),
            session_service: SessionRepository::new(adapters.session_adapter, driver),
            password_reset_token_service: PasswordResetTokenRepository::new(
                adapters.reset_token_adapter,
                driver,
            ),
            email_verification_token_service: EmailVerificationTokenRepository::new(
                adapters.email_verification_token,
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

        let client = MemCache::start("").await?;
        let memcache = MemCacheAdapter::new(client);

        Ok(Self::new(adapters, DatabaseDriver::SQLite, memcache))
    }

    async fn from_mongo(conn: &str) -> Result<Self> {
        let db = MongoDB::start(conn).await?;
        let adapters = DatabaseAdapters::mongodb(&db);

        let client = MemCache::start("").await?;
        let memcache = MemCacheAdapter::new(client);

        Ok(Self::new(adapters, DatabaseDriver::MongoDB, memcache))
    }
}
