mod app_state;
mod configuration;
pub mod database;
mod environment;
mod server;

pub use app_state::AppState;
pub use configuration::*;

use environment::*;
use server::ServerConfig;

use database::config::DatabaseConfig;
use database::driver::DatabaseDriver;

#[derive(Debug, serde::Deserialize)]
pub struct AppConfig {
    pub name: String,
    pub config_dir: String,
    pub config_path: String,
    pub server: ServerConfig,
    pub database: DatabaseConfig,
}

impl AppConfig {
    fn env() -> Environment {
        std::env::var("ENV")
            .unwrap_or_else(|_| Environment::Dev.as_str().into())
            .try_into()
            .expect("Failed to parse ENV")
    }
    fn db() -> DatabaseDriver {
        std::env::var("DB")
            .unwrap_or_else(|_| DatabaseDriver::SQLite.as_str().into())
            .try_into()
            .expect("Failed to parse DB")
    }

    pub fn load() -> Result<AppConfig, config::ConfigError> {
        let environment: Environment = Self::env();
        let environment_path = format!("{}.yaml", environment.as_str());

        let environment_database: DatabaseDriver = Self::db();
        let database_path = format!(
            "{}/{}.yaml",
            environment_database.as_str(),
            environment.as_str(),
        );

        let value = match environment {
            Environment::Dev => "app/configuration",
            Environment::Prod => "/app/configuration",
        };
        let config_dir = std::path::PathBuf::from(value);

        let settings = config::Config::builder()
            .add_source(config::File::from(config_dir.join("base.yaml")).required(true))
            .add_source(config::File::from(config_dir.join(environment_path)))
            .add_source(config::File::from(config_dir.join(database_path)))
            .build()
            .map_err(|e| dbg!(e))?;

        settings.try_deserialize::<AppConfig>()
    }
}
