use sqlx::{Executor, Pool, Sqlite, SqlitePool};

use crate::error::Error;

pub struct SQLite {}
impl SQLite {
    pub async fn start(conn: &str) -> Result<Pool<Sqlite>, Error> {
        let pool = SqlitePool::connect(conn).await.map_err(|e| {
            dbg!(&e);
            Error::InternalServerError(e.to_string())
        })?;

        pool.execute("PRAGMA foreign_keys = ON;")
            .await
            .map_err(|e| {
                dbg!(&e);
                Error::InternalServerError(e.to_string())
            })?;

        Ok(pool)
    }
}
