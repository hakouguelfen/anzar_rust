use actix_web::{
    Error,
    body::MessageBody,
    dev::{ServiceRequest, ServiceResponse},
    middleware::Next,
};
use serde_json::{Value, json};
use std::{net::IpAddr, str::FromStr};

use super::{RATE_LIMITS, TokenBucket};
use crate::error::Error as AuthError;

fn parse_error(error: AuthError) -> Value {
    json!({"message": error.to_string()})
}
fn extract_ipadd(req: &ServiceRequest) -> Option<String> {
    req.headers()
        .get("x-forwarded-for")
        .or_else(|| req.headers().get("X-Forwarded-For"))
        .or_else(|| req.headers().get("x-real-ip"))
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.split(',').next())
        .and_then(|s| IpAddr::from_str(s.trim()).ok())
        .or_else(|| req.peer_addr().map(|a| a.ip()))
        .map(|a| a.to_canonical().to_string())
}

pub async fn ip_rate_limit_middleware(
    req: ServiceRequest,
    next: Next<impl MessageBody>,
) -> Result<ServiceResponse<impl MessageBody>, Error> {
    let ipadd =
        extract_ipadd(&req).ok_or(actix_web::error::ErrorInternalServerError(parse_error(
            AuthError::InternalServerError("extract configuraiton".into()),
        )))?;

    let mut bucket = RATE_LIMITS.entry(ipadd).or_insert_with(TokenBucket::ip);
    bucket.run()?;

    dbg!("IP RateLimit");
    println!("{:?}", *bucket);

    next.call(req).await
}
