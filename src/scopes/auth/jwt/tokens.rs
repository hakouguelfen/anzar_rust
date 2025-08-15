use chrono::Duration;
use jsonwebtoken::{EncodingKey, Validation, decode};
use jsonwebtoken::{Header, encode, errors::Error};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::core::extractors::{Claims, TokenType};
use crate::scopes::auth;

use super::keys::KEYS;

pub type Result<T> = core::result::Result<T, Error>;

impl From<jsonwebtoken::errors::Error> for auth::Error {
    fn from(_: jsonwebtoken::errors::Error) -> Self {
        Self::TokenCreationFailed
    }
}

#[derive(Default)]
pub struct JwtDecoderBuilder {
    token: String,
    token_type: TokenType,
}
impl JwtDecoderBuilder {
    pub fn new() -> Self {
        JwtDecoderBuilder::default()
    }

    pub fn with_token(mut self, token: impl Into<String>) -> Self {
        self.token = token.into();
        self
    }
    pub fn with_token_type(mut self, token_type: impl Into<TokenType>) -> Self {
        self.token_type = token_type.into();
        self
    }

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

#[derive(Default)]
pub struct JwtEncoderBuilder {
    user_id: String,
}
impl JwtEncoderBuilder {
    pub fn with_user_id(mut self, user_id: impl Into<String>) -> Self {
        self.user_id = user_id.into();
        self
    }

    pub fn build(&self) -> Result<Tokens> {
        let access_key = &KEYS.encoding_acc_tok;
        let refresh_key = &KEYS.encoding_ref_tok;

        let access_token = self.encode(
            &self.user_id,
            TokenType::AccessToken,
            access_key,
            Duration::minutes(15),
            &Uuid::new_v4().to_string(),
        )?;
        let refresh_token_jti = Uuid::new_v4().to_string();
        let refresh_token = self.encode(
            &self.user_id,
            TokenType::RefreshToken,
            refresh_key,
            Duration::days(15),
            &refresh_token_jti,
        )?;

        let tokens: Tokens = Tokens::new()
            .with_access_token(&access_token)
            .with_refresh_token(&refresh_token)
            .with_jti(&refresh_token_jti);

        Ok(tokens)
    }

    pub fn encode(
        &self,
        sub: &String,
        token_type: TokenType,
        key: &EncodingKey,
        duration: Duration,
        jti: &String,
    ) -> Result<String> {
        let claims = Claims::new(sub, token_type, duration, jti);
        encode(&Header::default(), &claims, key)
    }
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct Tokens {
    #[serde(rename = "accessToken")]
    pub access_token: String,

    #[serde(rename = "refreshToken")]
    pub refresh_token: String,

    pub refresh_token_jti: String,
}
impl Tokens {
    pub fn new() -> Self {
        Tokens::default()
    }

    pub fn with_access_token(mut self, access_token: &String) -> Self {
        self.access_token = access_token.to_string();
        self
    }

    pub fn with_refresh_token(mut self, refresh_token: &String) -> Self {
        self.refresh_token = refresh_token.to_string();
        self
    }

    pub fn with_jti(mut self, jti: &String) -> Self {
        self.refresh_token_jti = jti.to_string();
        self
    }
}
