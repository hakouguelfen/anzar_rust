use crate::error::{Error, Result};
use argon2::{
    Argon2, PasswordHash, PasswordHasher, PasswordVerifier,
    password_hash::{SaltString, rand_core::OsRng},
};
use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};
use rand::TryRngCore;
use sha2::{Digest, Sha256};

pub trait AuthenticationHasher {
    fn hash_token(token: &str) -> String;
    fn _verify_token(token: &str, stored_hash: &str) -> bool;
    fn generate_token(length: usize) -> String;
    fn hash_password(password: &str) -> Result<String>;
    fn verify_password(password: &str, hash: &str) -> bool;
}

pub struct Utils;
impl AuthenticationHasher for Utils {
    fn hash_token(token: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(token.as_bytes());

        format!("{:x}", hasher.finalize())
    }

    fn _verify_token(token: &str, stored_hash: &str) -> bool {
        Self::hash_token(token) == stored_hash
    }

    fn hash_password(password: &str) -> Result<String> {
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

    fn verify_password(password: &str, hash: &str) -> bool {
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

    fn generate_token(length: usize) -> String {
        let mut bytes = vec![0u8; length];
        // FIXME: handle the Result
        let _ = rand::rngs::OsRng.try_fill_bytes(&mut bytes);
        BASE64_URL_SAFE_NO_PAD.encode(&bytes)
    }
}
