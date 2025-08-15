use mongodb::{Database, bson::oid::ObjectId};

use crate::{
    core::extractors::AuthPayload,
    scopes::auth::{
        DatabaseJWTRepo, Error, JWTRepo, Result,
        jwt::model::{RefreshToken, RefreshTokenFilter},
        utils::{AuthenticationHasher, Utils},
    },
};

#[derive(Debug)]
pub struct JWTService {
    repository: DatabaseJWTRepo,
}

impl JWTService {
    pub fn new(db: &Database) -> Self {
        Self {
            repository: DatabaseJWTRepo::new(db),
        }
    }

    pub async fn insert(&self, refresh_token: RefreshToken) -> Result<()> {
        self.repository.insert(refresh_token).await.map_err(|e| {
            tracing::error!("Failed to insert refreshToken to database: {:?}", e);
            Error::TokenCreationFailed
        })?;

        Ok(())
    }

    pub async fn find(&self, payload: AuthPayload) -> Option<RefreshToken> {
        let user_id: ObjectId = ObjectId::parse_str(&payload.user_id).unwrap_or_default();
        let filter = RefreshTokenFilter {
            jti: payload.jti,
            user_id,
            hash: Utils::hash_token(&payload.refresh_token),
            valid: true,
        };

        self.repository.find_by_filter(filter).await
    }

    pub async fn invalidate(&self, jti: String) -> Result<RefreshToken> {
        self.repository.invalidate(jti).await.ok_or_else(|| {
            tracing::error!("Failed to invalidate refreshToken");
            Error::TokenRevocationFailed
        })
    }
    pub async fn revoke(&self, user_id: ObjectId) -> Result<()> {
        self.repository.revoke(user_id).await.map_err(|e| {
            tracing::error!("Failed to revoke tokens after security breach: {:?}", e);
            Error::TokenRevocationFailed
        })?;

        Ok(())
    }
}
