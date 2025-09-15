use secrecy::SecretString;

use crate::parser::AdapterType;

// use crate::scopes::config::Configuration;
// use std::sync::{LazyLock, Mutex};
// static APP_CONFIG: LazyLock<Mutex<Configuration>> =
//     LazyLock::new(|| Mutex::new(Configuration::default()));
//
// pub fn update_app_config(config: Configuration) {
//     *APP_CONFIG.lock().unwrap() = config;
// }
// pub fn get_app_config() -> Configuration {
//     let s = APP_CONFIG.lock().unwrap();
//     s.clone()
// }

#[derive(serde::Deserialize)]
pub struct Settings {
    pub application: ApplicationSettings,
    pub database: DatabaseSettings,
}

#[derive(serde::Deserialize)]
pub struct ApplicationSettings {
    pub port: u16,
    pub host: String,
    pub jwt_acc_secret: SecretString,
    pub jwt_ref_secret: SecretString,
}

#[derive(serde::Deserialize)]
pub struct DatabaseSettings {
    pub username: String,
    pub password: SecretString,
    pub port: String,
    pub host: String,
    pub database_name: String,
    pub db_type: AdapterType,
}

impl DatabaseSettings {
    pub fn connection_string(&self) -> String {
        match self.db_type {
            AdapterType::MongoDB => {
                // mongodb+srv://<username>:<password>@<host>:<port>/<db_name>
                // test: mongodb://localhost:27017/dev
                // prod: mongodb://db:27017/production
                format!(
                    "mongodb://{}:{}/{}",
                    self.host, self.port, self.database_name
                )
            }
            AdapterType::SQLite => self.database_name.to_string(),
            AdapterType::PostgreSQL => todo!(),
        }
    }
}

fn get_db_type(s: &str) -> &str {
    match s.to_lowercase().as_str() {
        "postgres" => "PostgreSQL",
        "mongodb" => "MongoDB",
        "sqlite" => "SQLite",
        _ => "SQLite",
    }
}

pub fn get_configuration() -> Result<Settings, config::ConfigError> {
    let base_path = std::env::current_dir().expect("Failed to determine the current directory");
    let config_dir = base_path.join("configuration");

    let environment: Environment = std::env::var("APP_ENV")
        .unwrap_or_else(|_| Environment::Dev.as_str().into())
        .try_into()
        .expect("Failed to parse APP_ENV");

    let environment_database: EnvironmentDatabase = std::env::var("APP_DB")
        .unwrap_or_else(|_| EnvironmentDatabase::SQLite.as_str().into())
        .try_into()
        .expect("Failed to parse APP_DB");

    let environment_filename = format!("{}.yaml", environment.as_str());
    let database_filename = format!(
        "{}/{}.yaml",
        environment_database.as_str(),
        environment.as_str(),
    );

    let db_type = get_db_type(environment_database.as_str());
    let settings = config::Config::builder()
        .add_source(config::File::from(config_dir.join("base.yaml")).required(true))
        .add_source(config::File::from(config_dir.join(environment_filename)))
        .add_source(config::File::from(config_dir.join(database_filename)))
        .set_override("database.db_type", db_type)? // <-- add new setting here
        // .add_source(
        //     config::Environment::with_prefix("APP")
        //         .prefix_separator("_")
        //         .separator("__"),
        // )
        .build()?;

    settings.try_deserialize::<Settings>()
}

pub enum EnvironmentDatabase {
    SQLite,
    PostgreSQL,
    MongoDB,
}
impl EnvironmentDatabase {
    pub fn as_str(&self) -> &'static str {
        match self {
            EnvironmentDatabase::SQLite => "sqlite",
            EnvironmentDatabase::MongoDB => "mongodb",
            EnvironmentDatabase::PostgreSQL => "postgresql",
        }
    }
}
impl TryFrom<String> for EnvironmentDatabase {
    type Error = String;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        match s.to_lowercase().as_str() {
            "sqlite" => Ok(Self::SQLite),
            "mongodb" => Ok(Self::MongoDB),
            "postgresql" => Ok(Self::PostgreSQL),
            other => Err(format!(
                "{} is not supported database. Use either `sqlite`, `postgresql` or `mongodb`",
                other
            )),
        }
    }
}

pub enum Environment {
    Dev,
    Prod,
}
impl Environment {
    pub fn as_str(&self) -> &'static str {
        match self {
            Environment::Dev => "dev",
            Environment::Prod => "prod",
        }
    }
}

impl TryFrom<String> for Environment {
    type Error = String;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        match s.to_lowercase().as_str() {
            "dev" => Ok(Self::Dev),
            "prod" => Ok(Self::Prod),
            other => Err(format!(
                "{} is not supported enironment. Use either `dev` or  `prod`",
                other
            )),
        }
    }
}
