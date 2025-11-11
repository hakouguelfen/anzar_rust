use crate::error::Error;

pub struct MemCache {}
impl MemCache {
    pub async fn start(conn: &str) -> Result<memcache::Client, Error> {
        let db = memcache::connect(conn).map_err(|e| {
            dbg!(&e);
            Error::InternalServerError(e.to_string())
        })?;

        Ok(db)
    }
}
