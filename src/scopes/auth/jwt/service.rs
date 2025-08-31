use chrono::Utc;
use mongodb::{
    Database,
    bson::{doc, oid::ObjectId},
};

use crate::{
    adapters::mongodb_adapter::{MongodbAdapter, MongodbAdapterTrait},
    core::extractors::AuthPayload,
    scopes::auth::{
        Error, Result,
        jwt::model::RefreshToken,
        utils::{AuthenticationHasher, Utils},
    },
};

#[derive(Debug, Clone)]
pub struct JWTService {
    mongodb_adapter: MongodbAdapter<RefreshToken>,
}

impl JWTService {
    pub fn new(db: &Database) -> Self {
        Self {
            mongodb_adapter: MongodbAdapter::new(db, "refresh-token"),
        }
    }

    pub async fn insert(&self, refresh_token: RefreshToken) -> Result<()> {
        self.mongodb_adapter
            .insert(refresh_token)
            .await
            .map_err(|e| {
                tracing::error!("Failed to insert refreshToken to database: {:?}", e);
                Error::TokenCreationFailed
            })?;

        Ok(())
    }

    pub async fn find(&self, payload: AuthPayload) -> Option<RefreshToken> {
        let user_id: ObjectId = ObjectId::parse_str(&payload.user_id).unwrap_or_default();
        let filter = doc! {
            "jti": payload.jti,
            "userId": user_id,
            "hash": Utils::hash_token(&payload.refresh_token),
            "valid": true
        };
        let update = doc! { "$set": doc! { "valid": false, "usedAt": Utc::now().to_string() } };

        self.mongodb_adapter
            .find_one_and_update(filter, update)
            .await
    }

    pub async fn find_by_jti(&self, jti: &str) -> Option<RefreshToken> {
        let filter = doc! {"jti": jti};
        self.mongodb_adapter.find_one(filter).await
    }

    pub async fn invalidate(&self, jti: String) -> Result<RefreshToken> {
        let filter = doc! {"jti": jti};
        let update = doc! { "$set": doc! { "valid": false, "usedAt": Utc::now().to_string() } };

        self.mongodb_adapter
            .find_one_and_update(filter, update)
            .await
            .ok_or_else(|| {
                tracing::error!("failed to invalidate token");
                Error::InvalidToken
            })
    }
    pub async fn revoke(&self, user_id: ObjectId) -> Result<()> {
        let filter = doc! {"userId": user_id};
        let update = doc! { "$set": doc! {"valid": false} };

        self.mongodb_adapter
            .update_many(filter, update)
            .await
            .map_err(|e| {
                tracing::error!("Failed to revoke tokens after security breach: {:?}", e);
                Error::TokenRevocationFailed
            })?;

        Ok(())
    }
}
