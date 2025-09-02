use std::sync::Arc;

use chrono::Utc;
use mongodb::bson::doc;
use serde_json::json;

use crate::{
    adapters::database_adapter::DatabaseAdapter,
    core::extractors::AuthPayload,
    scopes::auth::{
        Error, Result,
        jwt::model::RefreshToken,
        utils::{AuthenticationHasher, Utils},
    },
};

#[derive(Clone)]
pub struct JWTService {
    adapter: Arc<dyn DatabaseAdapter<RefreshToken>>,
}

impl JWTService {
    pub fn new(adapter: Arc<dyn DatabaseAdapter<RefreshToken>>) -> Self {
        Self { adapter }
    }

    pub async fn insert(&self, refresh_token: RefreshToken) -> Result<()> {
        self.adapter.insert(refresh_token).await.map_err(|e| {
            tracing::error!("Failed to insert refreshToken to database: {:?}", e);
            Error::TokenCreationFailed
        })?;

        Ok(())
    }

    pub async fn find(&self, payload: AuthPayload) -> Option<RefreshToken> {
        let filter = json! ({
            "jti": payload.jti,
            "userId": &payload.user_id,
            "hash": Utils::hash_token(&payload.refresh_token),
            "valid": true
        })
        .try_into()
        .ok()?;

        let update = json! ({
            "$set": json! ({
                "valid": false,
                "usedAt": Utc::now().to_string()
            })
        })
        .try_into()
        .ok()?;

        self.adapter.find_one_and_update(filter, update).await
    }

    pub async fn find_by_jti(&self, jti: &str) -> Option<RefreshToken> {
        let filter = json! ({"jti": jti});
        let filter = filter.try_into().ok()?;

        self.adapter.find_one(filter).await
    }

    pub async fn invalidate(&self, jti: String) -> Result<RefreshToken> {
        let filter = json! ({"jti": jti}).try_into()?;
        let update =
            json! ({ "$set": json! ({ "valid": false, "usedAt": Utc::now().to_string() }) })
                .try_into()?;

        self.adapter
            .find_one_and_update(filter, update)
            .await
            .ok_or_else(|| {
                tracing::error!("failed to invalidate token");
                Error::InvalidToken
            })
    }
    pub async fn revoke(&self, user_id: String) -> Result<()> {
        let filter = json! ({"userId": user_id}).try_into()?;
        let update = json! ({ "$set": doc! {"valid": false} }).try_into()?;

        self.adapter
            .update_many(filter, update)
            .await
            .map_err(|e| {
                tracing::error!("Failed to revoke tokens after security breach: {:?}", e);
                Error::TokenRevocationFailed
            })?;

        Ok(())
    }
}
