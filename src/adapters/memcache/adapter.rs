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
    pub fn get_attempts(&self, key: &str) -> u8 {
        if let Ok(Some(val)) = self.client.get::<String>(key) {
            return val.parse::<u8>().unwrap_or(0);
        }
        0
    }
    pub fn lock_account(&self, key: &str, expiration: u32) -> Result<(), memcache::MemcacheError> {
        self.client
            .add(&format!("lockout:{}", key), "locked", expiration)
    }
    pub fn contains_key(&self, key: &str) -> bool {
        if let Ok(val) = self.client.get::<String>(key) {
            return val.is_some();
        }

        false
    }
}
