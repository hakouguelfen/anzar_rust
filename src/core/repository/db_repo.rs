use mongodb::{Client, Database};
use std::env;

use crate::scopes::user;

pub struct DataBaseRepo;

const DATABASE_NAME: &str = "dev";

impl DataBaseRepo {
    pub async fn default() -> Database {
        let uri = env::var("DATABASE_URI").expect("Error loading env variable");
        let client = Client::with_uri_str(uri)
            .await
            .expect("Coudln't connect to DB");

        let db: Database = client.database(DATABASE_NAME);

        user::create_unique_email_index(&db)
            .await
            .expect("Could not create user email index");

        db
    }
}
