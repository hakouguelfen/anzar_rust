use std::sync::LazyLock;

use crate::error::Error;
use dashmap::DashMap;

pub static RATE_LIMITS: LazyLock<DashMap<String, TokenBucket>> = LazyLock::new(DashMap::new);

#[derive(Clone, Debug)]
pub struct TokenBucket {
    bucket_size: u32,
    refill_rate: u32,
    duration: chrono::Duration,
    last_refill: chrono::DateTime<chrono::Utc>,
}

impl Default for TokenBucket {
    fn default() -> Self {
        Self {
            bucket_size: 5,
            refill_rate: 5,
            duration: chrono::Duration::minutes(60),
            last_refill: chrono::Utc::now(),
        }
    }
}

impl TokenBucket {
    pub fn from_cache(token_bucket: TokenBucket) -> Self {
        token_bucket
    }
    pub fn ip() -> Self {
        Self {
            bucket_size: 100,
            refill_rate: 100,
            duration: chrono::Duration::minutes(1),
            last_refill: chrono::Utc::now(),
        }
    }
}
impl TokenBucket {
    pub fn with_bucket_size(mut self, bucket_size: u32) -> Self {
        self.bucket_size = bucket_size;
        self
    }
    pub fn with_refill_rate(mut self, refill_rate: u32) -> Self {
        self.refill_rate = refill_rate;
        self
    }
    pub fn with_duration(mut self, duration: chrono::Duration) -> Self {
        self.duration = duration;
        self
    }
}
impl TokenBucket {
    pub fn run(&mut self) -> Result<(), Error> {
        let time_since_refill = chrono::Utc::now() - self.last_refill;
        if time_since_refill >= self.duration {
            self.bucket_size = self.refill_rate;
            self.last_refill = chrono::Utc::now();
        }

        if self.bucket_size == 0 {
            return Err(Error::RateLimitExceeded {
                limit: self.bucket_size,
                window: self.duration,
            });
        }
        self.bucket_size -= 1;

        dbg!(self.bucket_size);

        Ok(())
    }
}
