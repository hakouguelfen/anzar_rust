use crate::error::{Error, Result};
use argon2::{
    Argon2, PasswordHash, PasswordHasher, PasswordVerifier,
    password_hash::{SaltString, rand_core::OsRng},
};
use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};
use hmac::Mac;
use rand::TryRngCore;
use sha2::{Digest, Sha256};

pub trait TokenHasher {
    fn generate(length: usize) -> String;
    fn hash(token: &str) -> String;
    fn verify(a: &str, b: &str) -> bool;
}

pub struct Token {}
impl TokenHasher for Token {
    fn generate(length: usize) -> String {
        let mut bytes = vec![0u8; length];
        // FIXME: handle the Result
        let _ = rand::rngs::OsRng.try_fill_bytes(&mut bytes);

        BASE64_URL_SAFE_NO_PAD.encode(&bytes)
    }

    fn hash(token: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(token.as_bytes());

        format!("{:x}", hasher.finalize())
    }

    fn verify(a: &str, b: &str) -> bool {
        if a.len() != b.len() {
            return false;
        }

        a.bytes()
            .zip(b.bytes())
            .fold(0, |acc, (a, b)| acc | (a ^ b))
            == 0
    }
}

pub trait CustomPasswordHasher {
    fn hash(password: &str) -> Result<String>;
    fn verify(password: &str, hash: &str) -> bool;
}
pub struct Password;
impl CustomPasswordHasher for Password {
    fn hash(password: &str) -> Result<String> {
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        let hash = argon2
            .hash_password(password.as_bytes(), &salt)
            .map_err(|e| {
                tracing::error!("Failed to hash user password: {:?}", e);
                Error::HashingFailure
            })?;

        Ok(hash.to_string())
    }

    fn verify(password: &str, hash: &str) -> bool {
        let Ok(hash) = PasswordHash::new(hash) else {
            tracing::error!(
                "Failed to Parse a password hash from a string in the PHC string format."
            );
            return false;
        };

        Argon2::default()
            .verify_password(password.as_bytes(), &hash)
            .is_ok()
    }
}

pub struct DeviceCookie {
    id: String,
    nonce: String, // CSRNG
    secret_key: String,
}
impl DeviceCookie {
    pub fn new(secret_key: &str) -> Self {
        Self {
            id: String::default(),
            nonce: String::default(),
            secret_key: secret_key.into(),
        }
    }
    pub fn issue(&mut self, id: &str) -> String {
        self.nonce = Token::generate(32);
        self.id = id.into();

        let mut mac = hmac::Hmac::<sha2::Sha256>::new_from_slice(self.secret_key.as_bytes())
            .expect("HMAC can take key of any size");

        let message = format!("{}{}", self.id, self.nonce);
        mac.update(message.as_bytes());

        let signature = BASE64_URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());

        format!("{},{},{}", self.id, self.nonce, signature)
    }

    pub fn validate(&self, cookie_value: &str) -> bool {
        let parts: Vec<&str> = cookie_value.split(',').collect();
        if parts.len() != 3 {
            return false;
        }

        let user_id = parts[0];
        let nonce = parts[1];
        let signature = parts[2];

        let mut mac = hmac::Hmac::<Sha256>::new_from_slice(self.secret_key.as_bytes())
            .expect("HMAC can take key of any size");
        let message = format!("{}{}", user_id, nonce);
        mac.update(message.as_bytes());
        let expected = BASE64_URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());

        self.verify(&expected, signature)
    }

    fn verify(&self, a: &str, b: &str) -> bool {
        if a.len() != b.len() {
            return false;
        }

        a.bytes()
            .zip(b.bytes())
            .fold(0, |acc, (a, b)| acc | (a ^ b))
            == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_device_cookie() {
        let mut dc = DeviceCookie::new("supersecretkey");
        let cookie = dc.issue("alice");

        assert!(dc.validate(&cookie));
        assert!(!dc.validate("alice,wrongnonce,badsig"));
    }
}
