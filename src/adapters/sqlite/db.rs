use sqlx::{Pool, Sqlite, sqlite::SqlitePoolOptions};

pub struct SQLite {}
impl SQLite {
    pub async fn start(conn: &str) -> Pool<Sqlite> {
        // FIXME: don't panic, return error message to user
        let db = SqlitePoolOptions::new()
            .connect(conn)
            .await
            .expect("Failed to connect to sqlite");

        dbg!("connected to sqlite");
        db
    }
}
