use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};
use hmac::Mac;
use rand::TryRngCore;

use crate::{
    scopes::user::User,
    utils::{CustomPasswordHasher, Password},
};

pub struct FakeUserGenerator {
    secret_key: String,
}

impl FakeUserGenerator {
    pub fn new(secret_key: &str) -> Self {
        Self {
            secret_key: secret_key.into(),
        }
    }

    pub fn generate_fake_user(&self, email: &str) -> User {
        // Use HMAC to derive deterministic but unpredictable fake user ID
        let mut mac = hmac::Hmac::<sha2::Sha256>::new_from_slice(self.secret_key.as_bytes())
            .expect("HMAC can take key of any size");
        mac.update(b"fake_user_id");
        mac.update(email.as_bytes());
        let result = mac.finalize().into_bytes();

        // Convert first 16 bytes to UUID
        let mut uuid_bytes = [0u8; 16];
        uuid_bytes.copy_from_slice(&result[..16]);
        let fake_id = uuid::Uuid::from_bytes(uuid_bytes);

        User {
            id: Some(fake_id.to_string()),
            username: "some name".to_string(),
            email: email.to_string(),
            verified: true,
            role: crate::scopes::user::Role::User,
            created_at: chrono::Utc::now(),
        }
    }

    pub fn generate_fake_hash(&self) -> String {
        // Generate different fake hash for each email
        let fake_password = {
            let mut bytes = [0u8; 32];
            let _ = rand::rngs::OsRng.try_fill_bytes(&mut bytes);
            BASE64_URL_SAFE_NO_PAD.encode(bytes)
        };

        Password::hash(&fake_password).unwrap_or_default()
    }
}
