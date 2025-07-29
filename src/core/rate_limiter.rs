use chrono::Utc;

use crate::scopes::{auth::Error, user::User};

pub struct RateLimiter {
    max_requests_per_hour: u32,
    max_requests_per_day: u32,
    lockout_duration: chrono::Duration,
}

impl Default for RateLimiter {
    fn default() -> Self {
        RateLimiter {
            max_requests_per_hour: 3,
            max_requests_per_day: 5,
            lockout_duration: chrono::Duration::hours(24),
        }
    }
}

impl RateLimiter {
    pub fn check_rate_limit(&self, user: &User) -> Result<(), Error> {
        if user.failed_reset_attempts >= 5 {
            // TODO: update user.accountBlocked = true
            return Err(Error::AccountSuspended);
        }

        // Check if user has exceeded daily limit
        if let Some(last_reset) = user.last_password_reset {
            let time_since_last = Utc::now() - last_reset;
            if time_since_last < chrono::Duration::hours(1)
                && user.password_reset_count >= self.max_requests_per_hour
            {
                return Err(Error::RateLimitExceeded);
            }

            if time_since_last < chrono::Duration::days(1)
                && user.password_reset_count >= self.max_requests_per_day
            {
                return Err(Error::RateLimitExceeded);
            }
        }

        Ok(())
    }
}
