use super::driver::DatabaseDriver;
use secrecy::SecretString;

#[derive(Debug, serde::Deserialize)]
pub struct DatabaseConfig {
    pub username: String,
    pub password: SecretString,
    pub port: String,
    pub host: String,
    pub name: String,
    pub driver: DatabaseDriver,
}

impl DatabaseConfig {
    pub fn connection_string(&self) -> String {
        match self.driver {
            DatabaseDriver::MongoDB => {
                // mongodb+srv://<username>:<password>@<host>:<port>/<db_name>
                // test: mongodb://localhost:27017/dev
                // prod: mongodb://db:27017/production
                format!(
                    "mongodb://{}:{}/{}?retryWrites=false",
                    self.host, self.port, self.name
                )
            }
            DatabaseDriver::SQLite => self.name.to_string(),
            DatabaseDriver::PostgreSQL => todo!(),
        }
    }

    pub fn is_sql(&self) -> bool {
        matches!(
            self.driver,
            DatabaseDriver::SQLite | DatabaseDriver::PostgreSQL
        )
    }

    pub fn is_nosql(&self) -> bool {
        matches!(self.driver, DatabaseDriver::MongoDB)
    }
}
