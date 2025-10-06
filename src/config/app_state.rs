use std::fs;

use uuid::Uuid;

use crate::adapters::factory::DatabaseAdapters;
use crate::adapters::sqlite::SQLite;
use crate::config::{AppConfig, DatabaseDriver};
use crate::scopes::auth::service::AuthService;
use crate::scopes::config::{
    AuthStrategy, Authentication, Configuration, Database, EmailAndPassword,
};

#[derive(Clone)]
pub struct AppState {
    pub auth_service: AuthService,
    pub configuration: Configuration,
}

impl AppState {
    pub async fn prod(app_config: &AppConfig) -> Result<Self, std::io::Error> {
        let content = fs::read_to_string(&app_config.config)?;
        let configuration: Configuration = serde_yaml::from_str(content.as_str()).unwrap();
        let auth_service = AuthService::from_database(&configuration.database)
            .await
            .map_err(|e| std::io::Error::other(e.to_string()))?;

        Ok(Self {
            auth_service,
            configuration,
        })
    }

    pub async fn test(address: &str) -> Result<Self, std::io::Error> {
        let configuration = Self::build_config(address).await;
        let auth_service = Self::build_authservice(&configuration.database.connection_string)
            .await
            .map_err(|e| std::io::Error::other(e.to_string()))?;

        Ok(Self {
            auth_service,
            configuration,
        })
    }

    async fn build_config(address: &str) -> Configuration {
        let mut configuration = AppConfig::from_env().expect("Failed to read configuration");

        if configuration.database.is_nosql() {
            let db_name = Uuid::new_v4().to_string();
            configuration.database.name = db_name;
        }

        let connection_string = configuration.database.connection_string();

        Configuration {
            id: None,
            api_url: address.into(),
            database: Database {
                connection_string,
                driver: configuration.database.driver,
            },
            auth: Authentication {
                strategy: AuthStrategy::Jwt,
            },
            email_and_password: EmailAndPassword { enable: true },
        }
    }

    async fn build_authservice(conn: &str) -> Result<AuthService, crate::error::Error> {
        let driver = DatabaseDriver::SQLite;
        let db = SQLite::start(conn).await?;

        // NOTE: this is for running testing only
        // FIXME: move it to tests section
        if conn == "sqlite::memory:" {
            sqlx::migrate!("./migrations")
                .run(&db)
                .await
                .expect("migrations to run");
        }

        let adapters = DatabaseAdapters::sqlite(&db);

        Ok(AuthService::new(adapters, driver))
    }
}
