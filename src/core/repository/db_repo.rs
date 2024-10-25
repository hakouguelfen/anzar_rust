use mongodb::Database;

use crate::scopes::user;

pub struct DataBaseRepo;
impl DataBaseRepo {
    pub async fn start(connection_string: String) -> Database {
        let client = mongodb::Client::with_uri_str(&connection_string)
            .await
            .expect("Failed to connect to mongodb");
        let db = client
            .default_database()
            .expect("Failed to get default database");

        user::create_unique_email_index(&db)
            .await
            .expect("Could not create user email index");

        db
    }
}
