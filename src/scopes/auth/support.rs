use rand::Rng;

pub const DEVICE_COOKIE: &str = "__HOST-DeviceCookie";
pub const SESSION_COOKIE: &str = "__HOST-SessionID";
pub const CSRF_COOKIE: &str = "__HOST-CsrfToken";

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
