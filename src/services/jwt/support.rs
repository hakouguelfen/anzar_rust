use super::JwtDecoderBuilder;
use crate::error::{Error, InvalidTokenReason, Result, TokenErrorType};
use crate::extractors::{Claims, TokenType};

pub fn decode(token: &str, secret: &str) -> Result<Claims> {
    let decoding_secret = jsonwebtoken::DecodingKey::from_secret(secret.as_bytes());

    JwtDecoderBuilder::new(decoding_secret)
        .with_token(token)
        .with_token_type(TokenType::RefreshToken)
        .build()
        .map_err(|_| Error::InvalidToken {
            token_type: TokenErrorType::RefreshToken,
            reason: InvalidTokenReason::SignatureMismatch,
        })
}
