use std::fs;

use uuid::Uuid;

use crate::adapters::memcache::{MemCache, MemCacheAdapter};
use crate::adapters::{factory::DatabaseAdapters, mongodb::MongoDB, sqlite::SQLite};
use crate::config::{Configuration, Database, DatabaseDriver, EnvironmentConfig};
use crate::error::Result;
use crate::scopes::auth::service::AuthService;

#[derive(Clone)]
pub struct AppState {
    pub auth_service: AuthService,
    pub configuration: Configuration,
}

impl AppState {
    pub async fn prod(env_config: &EnvironmentConfig) -> Result<Self> {
        let content = fs::read_to_string(&env_config.config)?;
        let configuration: Configuration = serde_yaml::from_str(content.as_str())?;
        let auth_service = AuthService::from_database(&configuration.database).await?;

        Ok(Self {
            auth_service,
            configuration,
        })
    }

    pub async fn test(address: &str) -> Result<Self> {
        let configuration = Self::build_config(address).await?;
        let auth_service = Self::build_authservice(&configuration.database).await?;

        Ok(Self {
            auth_service,
            configuration,
        })
    }

    async fn build_config(address: &str) -> Result<Configuration> {
        let mut env_config = EnvironmentConfig::from_env().expect("Failed to read configuration");

        let content = fs::read_to_string(&env_config.config)?;
        let mut configuration: Configuration = serde_yaml::from_str(content.as_str())?;

        configuration.api_url = address.into();
        configuration.database.driver = env_config.database.driver;

        if configuration.database.driver == DatabaseDriver::MongoDB {
            let db_name = Uuid::new_v4().to_string();
            env_config.database.name = db_name;
        }

        configuration.database.connection_string = env_config.database.connection_string();

        Ok(configuration)
    }

    async fn build_authservice(database: &Database) -> Result<AuthService> {
        match database.driver {
            // DatabaseDriver::SQLite => Ok(Self::from_sqlite("/app/test.db".into()).await?),
            DatabaseDriver::SQLite => Ok(Self::from_sqlite(&database.connection_string).await?),
            DatabaseDriver::MongoDB => Ok(Self::from_mongo(&database.connection_string).await?),
            DatabaseDriver::PostgreSQL => todo!(),
        }
    }

    async fn from_sqlite(conn: &str) -> Result<AuthService> {
        let db = SQLite::start(conn).await?;
        if conn == "sqlite::memory:" {
            sqlx::migrate!("./migrations")
                .run(&db)
                .await
                .expect("migrations to run");
        }
        let adapters = DatabaseAdapters::sqlite(&db);

        let client = MemCache::start("").await?;
        let memcache = MemCacheAdapter::new(client);

        Ok(AuthService::new(adapters, DatabaseDriver::SQLite, memcache))
    }

    async fn from_mongo(conn: &str) -> Result<AuthService> {
        let db = MongoDB::start(conn).await?;
        let adapters = DatabaseAdapters::mongodb(&db);

        let client = MemCache::start("").await?;
        let memcache = MemCacheAdapter::new(client);
        Ok(AuthService::new(
            adapters,
            DatabaseDriver::MongoDB,
            memcache,
        ))
    }
}
