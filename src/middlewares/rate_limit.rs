use chrono::Utc;

use crate::error::Error;
use crate::scopes::user::User;

pub struct RateLimiter {
    max_requests_per_hour: u32,
    _max_requests_per_day: u32,
    lockout_duration: chrono::Duration,
}

impl Default for RateLimiter {
    fn default() -> Self {
        RateLimiter {
            max_requests_per_hour: 3,
            _max_requests_per_day: 5,
            lockout_duration: chrono::Duration::hours(24),
        }
    }
}

impl RateLimiter {
    pub fn check_rate_limit(&self, user: &User) -> Result<(), Error> {
        if user.failed_reset_attempts >= 5 {
            // TODO: update user.accountBlocked = true
            return Err(Error::AccountSuspended {
                user_id: user.clone().id.unwrap_or_default(),
            });
        }

        // Check if user has exceeded daily limit
        if let Some(reset_start) = user.password_reset_window_start {
            let time_since_reset = Utc::now() - reset_start;
            if time_since_reset < chrono::Duration::hours(1)
                && user.password_reset_count >= self.max_requests_per_hour
            {
                return Err(Error::RateLimitExceeded {
                    limit: self.max_requests_per_hour,
                    window: self.lockout_duration,
                });
            }
        }

        Ok(())
    }
}
