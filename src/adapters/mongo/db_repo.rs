use mongodb::Database;

use crate::adapters::mongo::indexes::MongodbIndexes;

pub struct MongoDB {}
impl MongoDB {
    pub async fn start(connection_string: String) -> Database {
        let client = mongodb::Client::with_uri_str(&connection_string)
            .await
            .expect("Failed to connect to mongodb");
        let db = client
            .default_database()
            .expect("Failed to get default database");

        let mongodb_indexes = MongodbIndexes { db: db.clone() };
        mongodb_indexes
            .create_unique_email_index()
            .await
            .expect("Could not create user email index");

        mongodb_indexes
            .create_token_hash_index()
            .await
            .expect("Could not create hash token index");

        db
    }
}
