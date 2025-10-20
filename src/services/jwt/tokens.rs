use jsonwebtoken::{Header, encode};
use jsonwebtoken::{Validation, decode};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::config::JWT;
use crate::error::Result;
use crate::extractors::{Claims, TokenType};

pub struct JwtDecoderBuilder {
    token: String,
    token_type: TokenType,
    decoding_secret: jsonwebtoken::DecodingKey,
}
impl JwtDecoderBuilder {
    pub fn new(decoding_secret: jsonwebtoken::DecodingKey) -> Self {
        Self {
            token: String::default(),
            token_type: TokenType::default(),
            decoding_secret,
        }
    }
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
        let claims =
            decode::<Claims>(&self.token, &self.decoding_secret, &Validation::default())?.claims;
        Ok(claims)
    }
    fn decode_refresh_token(&self) -> Result<Claims> {
        let claims =
            decode::<Claims>(&self.token, &self.decoding_secret, &Validation::default())?.claims;
        Ok(claims)
    }
}

pub struct JwtEncoderBuilder {
    user_id: String,
    encoding_secret: jsonwebtoken::EncodingKey,
    jwt_config: JWT,
}
impl JwtEncoderBuilder {
    pub fn new(user_id: &str, encoding_secret: jsonwebtoken::EncodingKey, jwt_config: JWT) -> Self {
        Self {
            user_id: user_id.into(),
            encoding_secret,
            jwt_config,
        }
    }

    pub fn build(&self) -> Result<Tokens> {
        let claims = Claims::new(
            &self.user_id,
            TokenType::AccessToken,
            chrono::Duration::seconds(self.jwt_config.expires_in),
            &uuid::Uuid::new_v4().to_string(),
        );
        let access_token = encode(&Header::default(), &claims, &self.encoding_secret)?;

        let refresh_token_jti = Uuid::new_v4().to_string();

        let claims = Claims::new(
            &self.user_id,
            TokenType::RefreshToken,
            chrono::Duration::seconds(self.jwt_config.refresh_expires_in),
            &refresh_token_jti,
        );
        let refresh_token = encode(&Header::default(), &claims, &self.encoding_secret)?;

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
