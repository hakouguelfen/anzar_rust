use mongodb::{Client, Database};
use std::env;

use crate::scopes::user;

pub struct DataBaseRepo;

impl DataBaseRepo {
    pub async fn default() -> Database {
        let uri = env::var("DATABASE_URI").expect("Error loading env variable");
        let db_name = env::var("DATABASE_NAME").expect("Error loading env variable");

        let client = Client::with_uri_str(uri)
            .await
            .expect("Coudln't connect to DB");
        let db: Database = client.database(&db_name);

        user::create_unique_email_index(&db)
            .await
            .expect("Could not create user email index");

        db
    }
}
