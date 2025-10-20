use std::sync::LazyLock;

use jsonwebtoken::{DecodingKey, EncodingKey};
use secrecy::ExposeSecret;

use crate::config::EnvironmentConfig;

pub struct Keys {
    pub encoding_secret: EncodingKey,
    pub decoding_secret: DecodingKey,
}

impl Keys {
    pub fn new(anzar_secret: &[u8]) -> Self {
        Self {
            encoding_secret: EncodingKey::from_secret(anzar_secret),
            decoding_secret: DecodingKey::from_secret(anzar_secret),
        }
    }
}

pub static KEYS: LazyLock<Keys> = LazyLock::new(|| {
    // FIXME: Fix this, use middleware or pass it as app_data in startup
    let configuration = EnvironmentConfig::from_env().expect("Failed to read configuration");

    let anzar_secret = configuration.server.anzar_secret;

    Keys::new(anzar_secret.expose_secret().as_bytes())
});
