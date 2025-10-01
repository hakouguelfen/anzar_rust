use std::sync::Arc;

use chrono::{Duration, Utc};
use serde_json::json;

use crate::error::{Error, InvalidTokenReason, Result, TokenErrorType};
use crate::utils::parser::Parser;
use crate::utils::{AuthenticationHasher, Utils};
use crate::{adapters::DatabaseAdapter, config::DatabaseDriver, services::session::model::Session};

#[derive(Clone)]
pub struct SessionService {
    adapter: Arc<dyn DatabaseAdapter<Session>>,
    database_driver: DatabaseDriver,
}

impl SessionService {
    pub fn new(
        adapter: Arc<dyn DatabaseAdapter<Session>>,
        database_driver: DatabaseDriver,
    ) -> Self {
        Self {
            adapter,
            database_driver,
        }
    }
}

impl SessionService {
    pub async fn insert(&self, session: Session) -> Result<()> {
        self.adapter.insert(session).await.map_err(|e| {
            tracing::error!("Failed to insert SessionId to database: {:?}", e);
            Error::TokenCreationFailed {
                token_type: TokenErrorType::SessionToken,
            }
        })?;

        Ok(())
    }

    pub async fn find(&self, token: String) -> Result<Session> {
        let filter = json! ({"token": Utils::hash_token(&token)});
        let filter = Parser::mode(self.database_driver).convert(filter);

        match self.adapter.find_one(filter).await {
            Ok(Some(session)) => Ok(session),
            Ok(None) => Err(Error::InvalidToken {
                token_type: TokenErrorType::SessionToken,
                reason: InvalidTokenReason::NotFound,
            }),
            Err(err) => Err(err),
        }
    }

    pub async fn extend_timeout(&self, id: String) -> Result<Session> {
        let filter = Parser::mode(self.database_driver).convert(json!({"id": id}));
        let update = json!({
            "$set": json!({
                "updatedAt": Utc::now(),
                "expiresAt": Utc::now() + Duration::hours(24),
            })
        });
        let update = Parser::mode(self.database_driver).convert(update);

        self.adapter
            .find_one_and_update(filter, update)
            .await
            .ok_or_else(|| Error::DatabaseError("".into()))
    }

    pub async fn invalidate(&self, token: String) -> Result<()> {
        let filter = json! ({"token": Utils::hash_token(&token)});
        let filter = Parser::mode(self.database_driver).convert(filter);

        self.adapter.delete_one(filter).await
    }

    pub async fn revoke(&self, user_id: String) -> Result<()> {
        let filter = Parser::mode(self.database_driver).convert(json!({"userId": user_id}));

        self.adapter.delete_many(filter).await.map_err(|e| {
            tracing::error!("Failed to revoke session after security breach: {:?}", e);
            Error::TokenRevocationFailed {
                token_id: "".into(),
            }
        })
    }
}
