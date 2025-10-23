use crate::error::{Error, Result};
use argon2::{
    Argon2, PasswordHash, PasswordHasher, PasswordVerifier,
    password_hash::{SaltString, rand_core::OsRng},
};
use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};
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
