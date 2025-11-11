use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};
use hmac::Mac;

use crate::scopes::user::User;

pub struct FakeUserGenerator {
    secret_key: [u8; 32],
}

impl FakeUserGenerator {
    pub fn new(secret_key: &[u8]) -> Self {
        let mut key = [0u8; 32];
        key.copy_from_slice(&secret_key[..32]);
        Self { secret_key: key }
    }

    pub fn generate_fake_user_data(&self, email: &str) -> (User, String) {
        // Derive fake data from email + secret key (deterministic but unpredictable)
        let fake_user = self.generate_fake_user(email);
        let fake_hash = self.generate_fake_password_hash(email);

        (fake_user, fake_hash)
    }

    fn generate_fake_user(&self, email: &str) -> User {
        // Use HMAC to derive deterministic but unpredictable fake user ID
        let mut mac = hmac::Hmac::<sha2::Sha256>::new_from_slice(&self.secret_key)
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
            verified: false,
            role: crate::scopes::user::Role::User,
            created_at: chrono::Utc::now(),
        }
    }

    fn generate_fake_password_hash(&self, email: &str) -> String {
        // Generate different fake hash for each email
        let mut mac = hmac::Hmac::<sha2::Sha256>::new_from_slice(&self.secret_key)
            .expect("HMAC can take key of any size");
        mac.update(b"fake_password_hash");
        mac.update(email.as_bytes());
        let result = mac.finalize().into_bytes();

        // Create realistic-looking Argon2 hash format
        let salt = &result[..16];
        let fake_hash_content = &result[16..32];

        format!(
            "$argon2id$v=19$m=19456,t=2,p=1${}${}",
            BASE64_URL_SAFE_NO_PAD.encode(salt),
            BASE64_URL_SAFE_NO_PAD.encode(fake_hash_content)
        )
    }
}
