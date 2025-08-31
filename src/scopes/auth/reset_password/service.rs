use crate::{
    adapters::mongo::{MongodbAdapter, MongodbAdapterTrait},
    scopes::auth::{Error, Result},
};

use super::model::PasswordResetTokens;
use chrono::Utc;
use mongodb::{
    Database,
    bson::{doc, oid::ObjectId},
};

#[derive(Debug, Clone)]
pub struct PasswordResetTokenService {
    mongodb_adapter: MongodbAdapter<PasswordResetTokens>,
}

impl PasswordResetTokenService {
    pub fn new(database: &Database) -> Self {
        Self {
            mongodb_adapter: MongodbAdapter::new(database, "password_reset_token"),
        }
    }

    pub async fn revoke(&self, user_id: ObjectId) -> Result<()> {
        let filter = doc! {"userId": user_id};
        let update = doc! { "$set": doc! {"valid": false} };
        self.mongodb_adapter
            .update_many(filter, update)
            .await
            .map_err(|e| {
                tracing::error!("Failed to revoke password tokens: {:?}", e);
                Error::TokenRevocationFailed
            })?;

        Ok(())
    }

    pub async fn insert(&self, otp: PasswordResetTokens) -> Result<()> {
        self.mongodb_adapter
            .insert(otp)
            .await
            .map(|_| ())
            .map_err(|e| {
                tracing::error!("Failed to insert password reset token to database: {:?}", e);
                Error::TokenCreationFailed
            })
    }

    pub async fn find(&self, hash: String) -> Result<PasswordResetTokens> {
        let filter = doc! {"tokenHash": hash};
        self.mongodb_adapter.find_one(filter).await.ok_or({
            tracing::error!("Password reset token not found");
            Error::TokenNotFound
        })
    }

    pub async fn invalidate(&self, id: ObjectId) -> Result<PasswordResetTokens> {
        let filter = doc! {"_id": id};
        let update = doc! { "$set": doc! { "valid": false, "usedAt": Utc::now().to_string() } };
        self.mongodb_adapter
            .find_one_and_update(filter, update)
            .await
            .ok_or({
                tracing::error!("Failed to invalidate token");
                Error::DatabaseError
            })
    }
}
