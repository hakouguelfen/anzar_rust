use crate::adapters::factory::DatabaseAdapters;
use crate::adapters::memcache::{MemCache, MemCacheAdapter};
use crate::adapters::{mongodb::MongoDB, sqlite::SQLite};

use crate::config::{Database, database::driver::DatabaseDriver};
use crate::error::Result;

use crate::scopes::auth::PasswordResetTokenRepository;
use crate::scopes::email::EmailVerificationTokenRepository;
use crate::scopes::user::UserRepository;
use crate::services::account::AccountRepository;
use crate::services::jwt::JWTRepository;
use crate::services::session::SessionRepository;
// use crate::services::transaction::repository::TransactionRepository;

#[derive(Clone)]
pub struct AuthService {
    pub(crate) user_service: UserRepository,
    pub(crate) account_service: AccountRepository,
    pub(crate) jwt_service: JWTRepository,
    pub(crate) session_service: SessionRepository,
    pub(crate) password_reset_token_service: PasswordResetTokenRepository,
    pub(crate) email_verification_token_service: EmailVerificationTokenRepository,
    // pub(crate) transaction_repository: TransactionRepository,
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
            // transaction_repository: TransactionRepository::new(adapters.transaction_adapter),
        }
    }
    pub async fn from_database(database: &Database) -> Result<Self> {
        let client = MemCache::start(&database.cache).await?;
        let memcache = MemCacheAdapter::new(client);

        let adapters = match database.driver {
            // DatabaseDriver::SQLite => Ok(Self::from_sqlite("/app/test.db".into()).await?),
            DatabaseDriver::SQLite => {
                let db = SQLite::start(&database.connection_string).await?;
                DatabaseAdapters::sqlite(&db)
            }
            DatabaseDriver::MongoDB => {
                let client = MongoDB::start(&database.connection_string).await?;
                let db_name = database.name().unwrap_or_default();
                DatabaseAdapters::mongodb(&client, db_name)
            }
            DatabaseDriver::PostgreSQL => todo!(),
        };

        Ok(Self::new(adapters, database.driver, memcache))
    }
}
