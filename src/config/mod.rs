mod app_state;
mod database;
mod environment;
mod server;

pub use app_state::AppState;
use database::DatabaseConfig;
pub use database::DatabaseDriver;
use environment::*;
use server::ServerConfig;

use crate::config::database::get_db_type;

#[derive(serde::Deserialize)]
pub struct AppConfig {
    pub name: String,
    pub config: String,
    pub server: ServerConfig,
    pub database: DatabaseConfig,
}

impl AppConfig {
    fn app_env() -> Environment {
        std::env::var("APP_ENV")
            .unwrap_or_else(|_| Environment::Dev.as_str().into())
            .try_into()
            .expect("Failed to parse APP_ENV")
    }
    fn db_env() -> EnvironmentDatabase {
        std::env::var("APP_DB")
            .unwrap_or_else(|_| EnvironmentDatabase::SQLite.as_str().into())
            .try_into()
            .expect("Failed to parse APP_DB")
    }

    pub fn from_env() -> Result<AppConfig, config::ConfigError> {
        let base_path = std::env::current_dir().expect("Failed to determine the current directory");
        let config_dir = base_path.join("src/config/configuration/");

        let environment: Environment = Self::app_env();
        let environment_filename = format!("{}.yaml", environment.as_str());

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
            .set_override("config", "/app/anzar.yml")?
            .set_override("database.driver", db_type)?
            .build()?;

        settings.try_deserialize::<AppConfig>()
    }
}
