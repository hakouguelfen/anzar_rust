use std::{env, sync::LazyLock};

use jsonwebtoken::{DecodingKey, EncodingKey};

pub struct Keys {
    pub encoding_acc_tok: EncodingKey,
    pub decoding_acc_tok: DecodingKey,

    pub encoding_ref_tok: EncodingKey,
    pub decoding_ref_tok: DecodingKey,
}

impl Keys {
    pub fn new(secret_acc_tok: &[u8], secret_ref_tok: &[u8]) -> Self {
        Self {
            encoding_acc_tok: EncodingKey::from_secret(secret_acc_tok),
            decoding_acc_tok: DecodingKey::from_secret(secret_acc_tok),

            encoding_ref_tok: EncodingKey::from_secret(secret_ref_tok),
            decoding_ref_tok: DecodingKey::from_secret(secret_ref_tok),
        }
    }
}

pub static KEYS: LazyLock<Keys> = LazyLock::new(|| {
    let acc_tok_secret = env::var("JWT_ACCESS_TOKEN_SECRET").expect("Error loading env variable");
    let ref_tok_secret = env::var("JWT_REFRESH_TOKEN_SECRET").expect("Error loading env variable");

    Keys::new(acc_tok_secret.as_bytes(), ref_tok_secret.as_bytes())
});
