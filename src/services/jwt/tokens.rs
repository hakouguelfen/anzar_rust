use jsonwebtoken::{Header, encode};
use jsonwebtoken::{Validation, decode};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::Result;
use crate::extractors::{Claims, TokenType};

use super::keys::KEYS;

#[derive(Default)]
pub struct JwtDecoderBuilder {
    token: String,
    token_type: TokenType,
}
impl JwtDecoderBuilder {
    pub fn with_token(mut self, token: impl Into<String>) -> Self {
        self.token = token.into();
        self
    }
    pub fn with_token_type(mut self, token_type: impl Into<TokenType>) -> Self {
        self.token_type = token_type.into();
        self
    }
}
impl JwtDecoderBuilder {
    pub fn build(&self) -> Result<Claims> {
        match self.token_type {
            TokenType::AccessToken => self.decode_access_token(),
            TokenType::RefreshToken => self.decode_refresh_token(),
        }
    }
    fn decode_access_token(&self) -> Result<Claims> {
        let key = &KEYS.decoding_acc_tok;
        let claims = decode::<Claims>(&self.token, key, &Validation::default())?.claims;
        Ok(claims)
    }
    fn decode_refresh_token(&self) -> Result<Claims> {
        let key = &KEYS.decoding_ref_tok;
        let claims = decode::<Claims>(&self.token, key, &Validation::default())?.claims;
        Ok(claims)
    }
}

pub struct JwtEncoderBuilder {
    user_id: String,
}
impl JwtEncoderBuilder {
    pub fn new(user_id: &str) -> Self {
        Self {
            user_id: user_id.into(),
        }
    }

    pub fn build(&self) -> Result<Tokens> {
        let access_key = &KEYS.encoding_acc_tok;
        let refresh_key = &KEYS.encoding_ref_tok;

        let claims = Claims::access_token(&self.user_id);
        let access_token = encode(&Header::default(), &claims, access_key)?;

        let refresh_token_jti = Uuid::new_v4().to_string();
        let claims = Claims::refresh_token(&self.user_id, &refresh_token_jti);
        let refresh_token = encode(&Header::default(), &claims, refresh_key)?;

        let tokens: Tokens = Tokens::default()
            .with_access_token(&access_token)
            .with_refresh_token(&refresh_token)
            .with_jti(&refresh_token_jti);

        Ok(tokens)
    }
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct Tokens {
    #[serde(rename = "accessToken")]
    pub access_token: String,

    #[serde(rename = "refreshToken")]
    pub refresh_token: String,

    #[serde(rename = "refreshTokenJti")]
    pub refresh_token_jti: String,
}
impl Tokens {
    pub fn with_access_token(mut self, access_token: &str) -> Self {
        self.access_token = access_token.into();
        self
    }

    pub fn with_refresh_token(mut self, refresh_token: &str) -> Self {
        self.refresh_token = refresh_token.into();
        self
    }

    pub fn with_jti(mut self, jti: &str) -> Self {
        self.refresh_token_jti = jti.into();
        self
    }
}
