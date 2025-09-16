use secrecy::SecretString;

#[derive(Debug, Default, Clone, Copy, serde::Deserialize, serde::Serialize, Eq, PartialEq)]
pub enum AdapterType {
    #[default]
    SQLite,
    PostgreSQL,
    MongoDB,
}

#[derive(serde::Deserialize)]
pub struct DatabaseConfig {
    pub username: String,
    pub password: SecretString,
    pub port: String,
    pub host: String,
    pub database_name: String,
    pub db_type: AdapterType,
}

impl DatabaseConfig {
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

    pub fn is_sql(&self) -> bool {
        matches!(self.db_type, AdapterType::SQLite | AdapterType::PostgreSQL)
    }

    pub fn is_nosql(&self) -> bool {
        matches!(self.db_type, AdapterType::MongoDB)
    }
}

pub fn get_db_type(s: &str) -> &str {
    match s.to_lowercase().as_str() {
        "postgres" | "postgresql" => "PostgreSQL",
        "mongodb" => "MongoDB",
        "sqlite" => "SQLite",
        _ => "SQLite",
    }
}
