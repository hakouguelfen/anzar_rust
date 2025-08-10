use mongodb::{bson::oid::ObjectId, Database};

use crate::scopes::auth::{
    jwt::model::RefreshToken,
    utils::{AuthenticationHasher, Utils},
    DatabaseJWTRepo, Error, JWTRepo, Result,
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

    pub async fn find(&self, user_id: ObjectId, refresh_token: &str) -> Result<RefreshToken> {
        let tokens = self.repository.find(user_id).await.ok_or_else(|| {
            tracing::error!("No refresh tokens found for user: {}", user_id);
            Error::InvalidToken
        })?;

        if tokens.is_empty() {
            tracing::warn!("No refresh tokens available for user: {}", user_id);
            return Err(Error::InvalidToken);
        }

        tokens
            .into_iter()
            .find(|token| Utils::verify_token(refresh_token, &token.hash))
            .ok_or_else(|| {
                tracing::warn!("Invalid refresh token for user: {}", user_id);
                Error::InvalidToken
            })
    }

    pub async fn invalidate(&self, token_id: ObjectId) -> Result<RefreshToken> {
        self.repository.invalidate(token_id).await.ok_or_else(|| {
            tracing::error!("Failed to invalidate refreshToken: {}", token_id);
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
