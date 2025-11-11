use rand::Rng;

use crate::error::Result;
use crate::utils::DeviceCookie;

pub fn construct_key_from_device_cookie(
    session: &actix_session::Session,
    device_cookie: &DeviceCookie,
    email: &str,
) -> Result<String> {
    if let Some(cookie) = session.get::<String>("DeviceCookie")? {
        match device_cookie.validate(&cookie) {
            Some(true) => Ok(format!("lockout:{}", cookie)),
            Some(false) => Ok(format!("lockout:user:{}", email)),
            None => Ok(format!("lockout:user:{}", email)),
        }
    } else {
        Ok(format!("lockout:user:{}", email))
    }
}

pub async fn delay(attempts: u32) {
    let base_secs = 2_u64.pow(attempts).min(12);
    let jitter = rand::random::<u64>() % 3;
    let duration = std::time::Duration::from_secs(base_secs + jitter);
    tokio::time::sleep(duration).await;
}

pub async fn throttle_since(start: std::time::Instant) {
    const TIMING_DELAY_MS: u64 = 800;

    let jitter = rand::rng().random_range(0..=20); // +/- 20ms
    let elapsed = start.elapsed().as_millis() as u64;
    let delay = TIMING_DELAY_MS.saturating_sub(elapsed) + jitter;

    if elapsed < TIMING_DELAY_MS {
        tokio::time::sleep(tokio::time::Duration::from_millis(delay)).await;
    }
}
