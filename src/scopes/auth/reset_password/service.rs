use crate::scopes::auth::{Error, Result};

use super::{DatabasePasswordResetTokenRepo, PasswordResetRepo, model::PasswordResetTokens};
use mongodb::{Database, bson::oid::ObjectId};

#[derive(Debug, Clone)]
pub struct PasswordResetTokenService {
    repository: DatabasePasswordResetTokenRepo,
}

impl PasswordResetTokenService {
    pub fn new(database: &Database) -> Self {
        Self {
            repository: DatabasePasswordResetTokenRepo::new(database),
        }
    }

    pub async fn revoke(&self, user_id: ObjectId) -> Result<()> {
        self.repository.revoke(user_id).await.map_err(|e| {
            tracing::error!("Failed to revoke password tokens: {:?}", e);
            Error::TokenRevocationFailed
        })?;

        Ok(())
    }

    pub async fn insert(&self, otp: PasswordResetTokens) -> Result<()> {
        self.repository.insert(otp).await.map(|_| ()).map_err(|e| {
            tracing::error!("Failed to insert password reset token to database: {:?}", e);
            Error::TokenCreationFailed
        })
    }

    pub async fn find(&self, hash: String) -> Result<PasswordResetTokens> {
        self.repository.find(hash).await.ok_or({
            tracing::error!("Password reset token not found");
            Error::TokenNotFound
        })
    }

    pub async fn invalidate(&self, id: ObjectId) -> Result<PasswordResetTokens> {
        self.repository.invalidate(id).await.ok_or({
            tracing::error!("Failed to invalidate token");
            Error::DatabaseError
        })
    }
}
