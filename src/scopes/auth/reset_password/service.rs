use std::sync::Arc;

use crate::{
    adapters::database_adapter::DatabaseAdapter,
    scopes::auth::{Error, Result},
};

use super::model::PasswordResetTokens;
use chrono::Utc;
use serde_json::json;

#[derive(Clone)]
pub struct PasswordResetTokenService {
    adapter: Arc<dyn DatabaseAdapter<PasswordResetTokens>>,
}
impl PasswordResetTokenService {
    pub fn new(adapter: Arc<dyn DatabaseAdapter<PasswordResetTokens>>) -> Self {
        Self { adapter }
    }

    pub async fn revoke(&self, user_id: String) -> Result<()> {
        let filter = json! ({"userId": user_id}).try_into()?;
        let update = json! ({ "$set": json! ({"valid": false}) }).try_into()?;

        self.adapter
            .update_many(filter, update)
            .await
            .map_err(|e| {
                tracing::error!("Failed to revoke password tokens: {:?}", e);
                Error::TokenRevocationFailed
            })?;

        Ok(())
    }

    pub async fn insert(&self, otp: PasswordResetTokens) -> Result<()> {
        self.adapter.insert(otp).await.map(|_| ()).map_err(|e| {
            tracing::error!("Failed to insert password reset token to database: {:?}", e);
            Error::TokenCreationFailed
        })
    }

    pub async fn find(&self, hash: String) -> Result<PasswordResetTokens> {
        let filter = json! ({"tokenHash": hash}).try_into()?;

        self.adapter.find_one(filter).await.ok_or({
            tracing::error!("Password reset token not found");
            Error::TokenNotFound
        })
    }

    pub async fn invalidate(&self, id: String) -> Result<PasswordResetTokens> {
        let filter = json! ({"_id": id}).try_into()?;
        let update = json! ({
            "$set": json! ({
                "valid": false,
                "usedAt": Utc::now().to_string()
            })
        })
        .try_into()?;

        self.adapter
            .find_one_and_update(filter, update)
            .await
            .ok_or({
                tracing::error!("Failed to invalidate token");
                Error::DatabaseError
            })
    }
}
