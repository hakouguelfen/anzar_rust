use actix_web::{Error, FromRequest, HttpRequest, dev::Payload};
use std::future::{Ready, ready};
use std::net::IpAddr;
use std::str::FromStr;

pub struct RemoteIp(pub Option<IpAddr>);

impl FromRequest for RemoteIp {
    type Error = Error;
    type Future = Ready<Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, _payload: &mut Payload) -> Self::Future {
        // try header first
        let ip = req
            .headers()
            .get("x-forwarded-for")
            .or_else(|| req.headers().get("X-Forwarded-For"))
            .or_else(|| req.headers().get("x-real-ip"))
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.split(',').next())
            .and_then(|s| IpAddr::from_str(s.trim()).ok())
            .or_else(|| req.peer_addr().map(|a| a.ip()));

        ready(Ok(RemoteIp(ip.map(|a| a.to_canonical()))))
    }
}
