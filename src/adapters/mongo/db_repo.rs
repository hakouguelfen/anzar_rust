use mongodb::Database;

use crate::{adapters::mongo::indexes::MongodbIndexes, error::Error};

pub struct MongoDB {}
impl MongoDB {
    pub async fn start(connection_string: String) -> Result<Database, Error> {
        let client = mongodb::Client::with_uri_str(&connection_string)
            .await
            .map_err(|e| Error::InternalServerError(e.to_string()))?;
        // .expect("Failed to connect to mongodb");
        let db = client
            .default_database()
            .ok_or_else(|| Error::InternalServerError("Failed to get default database".into()))?;
        // .expect("Failed to get default database");

        let mongodb_indexes = MongodbIndexes { db: db.clone() };
        mongodb_indexes
            .create_unique_email_index()
            .await
            .map_err(|e| Error::InternalServerError(e.to_string()))?;
        // .expect("Could not create user email index");

        mongodb_indexes
            .create_token_hash_index()
            .await
            .map_err(|e| Error::InternalServerError(e.to_string()))?;
        // .expect("Could not create hash token index");

        Ok(db)
    }
}
