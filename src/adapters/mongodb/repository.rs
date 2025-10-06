use mongodb::Database;

use crate::{adapters::mongodb::indexes::MongodbIndexes, error::Error};

pub struct MongoDB {}
impl MongoDB {
    pub async fn start(connection_string: &str) -> Result<Database, Error> {
        let client = mongodb::Client::with_uri_str(&connection_string)
            .await
            .map_err(|_| {
                Error::InternalServerError(format!(
                    "No available server found for connection string '{}'. Please verify that the connection string is valid and the server is reachable.",
                    connection_string
                ))
            })?;

        let db = client
            .default_database()
            .ok_or_else(|| 
                Error::InternalServerError("Failed to get default database: MongoDB client has no default database configured. Ensure 'default_database' is set in the connection string or client options.".into())
                )?;

        let mongodb_indexes = MongodbIndexes { db: db.clone() };
        mongodb_indexes
            .create_unique_email_index()
            .await
            .map_err(|e| Error::InternalServerError(e.to_string()))?;

        mongodb_indexes
            .create_token_hash_index()
            .await
            .map_err(|e| Error::InternalServerError(e.to_string()))?;

        Ok(db)
    }
}
