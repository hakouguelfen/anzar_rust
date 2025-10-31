use crate::error::Result;
use crate::utils::DeviceCookie;

pub fn construct_key_from_device_cookie(
    session: &actix_session::Session,
    device_cookie: &DeviceCookie,
    email: &str,
) -> Result<String> {
    if let Some(cookie) = session.get::<String>("DeviceCookie")? {
        match device_cookie.validate(&cookie) {
            true => Ok(format!("lockout:{}", cookie)),
            false => Ok(format!("lockout:user:{}", email)),
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
