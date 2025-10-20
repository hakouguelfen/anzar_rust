use std::sync::LazyLock;

use jsonwebtoken::{DecodingKey, EncodingKey};
use secrecy::ExposeSecret;

use crate::config::EnvironmentConfig;

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
    // FIXME: Fix this, use middleware or pass it as app_data in startup
    let configuration = EnvironmentConfig::from_env().expect("Failed to read configuration");

    let jwt_acc_secret = configuration.server.jwt_acc_secret;
    let jwt_ref_secret = configuration.server.jwt_ref_secret;

    Keys::new(
        jwt_acc_secret.expose_secret().as_bytes(),
        jwt_ref_secret.expose_secret().as_bytes(),
    )
});
