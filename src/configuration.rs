#[derive(serde::Deserialize)]
pub struct Settings {
    pub database: DatabaseSettings,
    pub port: u16,
}

#[derive(serde::Deserialize)]
pub struct DatabaseSettings {
    pub username: String,
    pub password: String,
    pub port: String,
    pub host: String,
    pub database_name: String,
}

impl DatabaseSettings {
    pub fn connection_string(&self) -> String {
        // mongodb+srv://<username>:<password>@<host>:<port>/<db_name>
        format!(
            "mongodb://{}:{}/{}",
            self.host, self.port, self.database_name
        )
    }
}

pub fn get_configuration() -> Result<Settings, config::ConfigError> {
    let settings = config::Config::builder()
        .add_source(config::File::with_name("configuration"))
        .build()
        .unwrap();

    let settings: Settings = settings.try_deserialize().unwrap();

    Ok(settings)
}
