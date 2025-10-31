#[derive(Clone)]
pub struct MemCacheAdapter {
    client: memcache::Client,
}

impl MemCacheAdapter {
    pub fn new(client: memcache::Client) -> Self {
        Self { client }
    }
}

impl MemCacheAdapter {
    pub fn increment(&self, key: &str) -> u8 {
        self.client.increment(key, 1).unwrap_or(0) as u8
    }
    pub fn lock_account(&self, key: &str, expiration: u32) -> Result<(), memcache::MemcacheError> {
        self.client
            .set(&format!("lockout:{}", key), "locked", expiration)
    }
    pub fn exists(&self, key: &str) -> bool {
        if let Ok(val) = self.client.get::<String>(key) {
            return val.is_some();
        }

        false
    }
}
