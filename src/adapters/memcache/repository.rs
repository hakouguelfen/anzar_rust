use crate::error::Error;

pub struct MemCache {}
impl MemCache {
    pub async fn start(_conn: &str) -> Result<memcache::Client, Error> {
        // TODO memcach should run inside docker (add in Dockerfile)
        let db = memcache::connect("memcache://127.0.0.1:23032").map_err(|e| {
            dbg!(&e);
            Error::InternalServerError(e.to_string())
        })?;

        Ok(db)
    }
}
