mod app_state;
mod configuration;
mod database;
mod environment;
mod runtime;
mod server;

pub use app_state::AppState;
pub use configuration::*;
use database::DatabaseConfig;
pub use database::DatabaseDriver;
use environment::*;
use runtime::Runtime;
use server::ServerConfig;

use crate::config::database::get_db_type;

#[derive(Debug, serde::Deserialize)]
pub struct EnvironmentConfig {
    pub name: String,
    pub config: String,
    pub server: ServerConfig,
    pub database: DatabaseConfig,
}

impl EnvironmentConfig {
    fn app_env() -> Environment {
        std::env::var("ENV")
            .unwrap_or_else(|_| Environment::Dev.as_str().into())
            .try_into()
            .expect("Failed to parse ENV")
    }
    fn db_env() -> EnvironmentDatabase {
        std::env::var("DB")
            .unwrap_or_else(|_| EnvironmentDatabase::SQLite.as_str().into())
            .try_into()
            .expect("Failed to parse DB")
    }
    fn runtime_env() -> Runtime {
        std::env::var("RUNTIME")
            .unwrap_or_else(|_| Runtime::Local.as_str().into())
            .try_into()
            .expect("Failed to parse RUNTIME")
    }

    pub fn from_env() -> Result<EnvironmentConfig, config::ConfigError> {
        let base_path = std::env::current_dir().expect("Failed to determine the current directory");
        let config_dir = base_path.join("configuration/");

        let environment: Environment = Self::app_env();
        let environment_filename = format!("{}.yaml", environment.as_str());

        let runtime = Self::runtime_env();
        let content: &str = match runtime {
            Runtime::Docker => "/app/anzar.yml",
            Runtime::Local => "./anzar.dev.yml",
        };

        let environment_database: EnvironmentDatabase = Self::db_env();
        let database_filename = format!(
            "{}/{}.yaml",
            environment_database.as_str(),
            environment.as_str(),
        );

        let db_type: &str = get_db_type(environment_database.as_str());
        let settings = config::Config::builder()
            .add_source(config::File::from(config_dir.join("base.yaml")).required(true))
            .add_source(config::File::from(config_dir.join(environment_filename)))
            .add_source(config::File::from(config_dir.join(database_filename)))
            .set_override("name", "Anzar")?
            .set_override("config", content)?
            .set_override("database.driver", db_type)?
            .build()?;

        settings.try_deserialize::<EnvironmentConfig>()
    }
}
