use dotenv::dotenv;
use std::env;

use mongodb::{Client, Database};

pub struct MongoRepo(Database);

impl MongoRepo {
    pub async fn init() -> Database {
        dotenv().ok();
        let uri = match env::var("DATABASE_URI") {
            Ok(v) => v.to_string(),
            Err(_) => format!("Error loading env variable"),
        };
        let client = Client::with_uri_str(uri).await;
        let db = client.unwrap().database("rustDB");

        db
    }
}
