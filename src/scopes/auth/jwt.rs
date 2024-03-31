use jsonwebtoken::{encode, errors::Error, EncodingKey, Header};
use serde::{Deserialize, Serialize};

use chrono::Utc;

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub exp: usize,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct Tokens {
    #[serde(rename = "accessToken")]
    pub access_token: String,
    #[serde(rename = "refreshToken")]
    pub refresh_token: String,
}

pub fn encode_tokens(sub: String, secret: String) -> Result<Tokens, Error> {
    let access_exp = (Utc::now().naive_utc() + chrono::Duration::minutes(30))
        .and_utc()
        .timestamp() as usize;
    let refresh_exp = (Utc::now().naive_utc() + chrono::naive::Days::new(15))
        .and_utc()
        .timestamp() as usize;

    let access_token = encode(
        &Header::default(),
        &Claims {
            sub: sub.clone(),
            exp: access_exp,
        },
        &EncodingKey::from_secret(secret.as_ref()),
    );
    let refresh_token = encode(
        &Header::default(),
        &Claims {
            sub,
            exp: refresh_exp,
        },
        &EncodingKey::from_secret(secret.as_ref()),
    );

    Ok(Tokens {
        access_token: access_token?,
        refresh_token: refresh_token?,
    })
}
