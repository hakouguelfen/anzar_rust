use sqlx::{Pool, Sqlite, sqlite::SqlitePoolOptions};

use crate::error::Error;

pub struct SQLite {}
impl SQLite {
    pub async fn start(conn: &str) -> Result<Pool<Sqlite>, Error> {
        dbg!(&conn);
        let db = SqlitePoolOptions::new().connect(conn).await.map_err(|e| {
            dbg!(&e);
            Error::InternalServerError(e.to_string())
        })?;

        Ok(db)
    }
}
