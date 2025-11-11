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
        let client = MemCache::start(&database.cache).await?;
        let memcache = MemCacheAdapter::new(client);

        let adapters = match database.driver {
            DatabaseDriver::SQLite => {
                let db = SQLite::start(&database.connection_string).await?;
                if &database.connection_string == "sqlite::memory:" {
                    sqlx::migrate!("./migrations")
                        .run(&db)
                        .await
                        .expect("migrations to run");
                }
                DatabaseAdapters::sqlite(&db)
            }
            DatabaseDriver::MongoDB => {
                let db = MongoDB::start(&database.connection_string).await?;
                DatabaseAdapters::mongodb(&db)
            }
            DatabaseDriver::PostgreSQL => todo!(),
        };

        Ok(AuthService::new(adapters, database.driver, memcache))
    }
}
