use std::sync::Arc;

use chrono::Utc;
use mongodb::bson::doc;
use serde_json::json;

use super::RefreshToken;
use crate::{
    adapters::DatabaseAdapter,
    config::DatabaseDriver,
    error::{Error, InvalidTokenReason, Result, TokenErrorType},
    extractors::AuthPayload,
    utils::{Token, TokenHasher, parser::Parser},
};

#[derive(Clone)]
pub struct JWTRepository {
    adapter: Arc<dyn DatabaseAdapter<RefreshToken>>,
    database_driver: DatabaseDriver,
}

impl JWTRepository {
    pub fn new(
        adapter: Arc<dyn DatabaseAdapter<RefreshToken>>,
        database_driver: DatabaseDriver,
    ) -> Self {
        Self {
            adapter,
            database_driver,
        }
    }

    pub async fn insert(&self, refresh_token: RefreshToken) -> Result<()> {
        self.adapter.insert(refresh_token).await.map_err(|e| {
            tracing::error!("Failed to insert refreshToken to database: {:?}", e);
            Error::TokenCreationFailed {
                token_type: TokenErrorType::RefreshToken,
            }
        })?;

        Ok(())
    }

    pub async fn find_and_consume(&self, payload: AuthPayload) -> Result<RefreshToken> {
        let filter = json! ({
            "jti": payload.jti,
            "userId": &payload.user_id,
            "token": Token::hash(&payload.refresh_token),
            "valid": true
        });
        let filter = Parser::mode(self.database_driver).convert(filter);

        let update = json! ({
            "$set": json! ({
                "valid": false,
                "usedAt": Utc::now()
            })
        });
        let update = Parser::mode(self.database_driver).convert(update);

        match self.adapter.find_one_and_update(filter, update).await {
            Ok(Some(refresh_token)) => Ok(refresh_token),
            Ok(None) => Err(Error::InvalidToken {
                token_type: TokenErrorType::RefreshToken,
                reason: crate::error::InvalidTokenReason::NotFound,
            }),
            Err(err) => Err(err),
        }
    }

    pub async fn find_by_jti(&self, jti: &str) -> Result<RefreshToken> {
        let filter = Parser::mode(self.database_driver).convert(json!({"jti": jti}));

        match self.adapter.find_one(filter).await {
            Ok(Some(token)) => Ok(token),
            Ok(None) => Err(Error::InvalidToken {
                token_type: TokenErrorType::RefreshToken,
                reason: InvalidTokenReason::NotFound,
            }),
            Err(err) => Err(err),
        }
    }

    pub async fn invalidate(&self, jti: &str) -> Result<RefreshToken> {
        let filter = Parser::mode(self.database_driver).convert(json!({"jti": jti}));
        let update = json! ({ "$set": json! ({ "valid": false, "usedAt": Utc::now() }) });
        let update = Parser::mode(self.database_driver).convert(update);

        match self.adapter.find_one_and_update(filter, update).await {
            Ok(Some(refresh_token)) => Ok(refresh_token),
            Ok(None) => Err(Error::InvalidToken {
                token_type: TokenErrorType::RefreshToken,
                reason: crate::error::InvalidTokenReason::Malformed,
            }),
            Err(err) => Err(err),
        }
    }
    pub async fn revoke(&self, user_id: &str) -> Result<()> {
        let filter = Parser::mode(self.database_driver).convert(json!({"userId": user_id}));
        let update = json! ({ "$set": doc! {"valid": false} });
        let update = Parser::mode(self.database_driver).convert(update);

        self.adapter
            .update_many(filter, update)
            .await
            .map_err(|e| {
                tracing::error!("Failed to revoke tokens after security breach: {:?}", e);
                Error::TokenRevocationFailed {
                    token_id: "".into(),
                }
            })?;

        Ok(())
    }
}
