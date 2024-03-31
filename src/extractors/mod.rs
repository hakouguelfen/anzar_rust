use std::future::{ready, Ready};

use actix_web::{
    dev::Payload, error::ErrorUnauthorized, http::header, web, Error as ActixWebError, FromRequest,
    HttpRequest,
};
use jsonwebtoken::{decode, DecodingKey, Validation};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct AuthToken {
    pub user_id: String,
    pub refresh_token: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    exp: usize,
}

impl FromRequest for AuthToken {
    type Error = ActixWebError;
    type Future = Ready<Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, _: &mut Payload) -> Self::Future {
        let auth_header: Option<&header::HeaderValue> = req.headers().get(header::AUTHORIZATION);
        let auth_token: String = auth_header.unwrap().to_str().unwrap_or("").to_string();

        let token: Vec<&str> = auth_token.split_ascii_whitespace().collect();
        let mut refresh_token: Option<String> = None;
        if req.path() == "/auth/refreshToken" {
            refresh_token = Some(token[1].to_string());
        }

        let secret: String = req.app_data::<web::Data<String>>().unwrap().to_string();
        let decoded = decode::<Claims>(
            &token[1],
            &DecodingKey::from_secret(secret.as_ref()),
            &Validation::default(),
        );
        match decoded {
            Ok(tok) => ready(Ok(AuthToken {
                user_id: tok.claims.sub,
                refresh_token,
            })),
            Err(_) => ready(Err(ErrorUnauthorized("Unauthorized"))),
        }
    }
}
