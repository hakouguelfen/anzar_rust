use std::sync::Arc;

use serde_json::json;

use crate::error::{Error, Result, TokenErrorType};
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

    pub async fn find(&self, token: String) -> Option<Session> {
        let filter = json! ({"token": Utils::hash_token(&token)});
        let filter = Parser::mode(self.database_driver).convert(filter);

        self.adapter.find_one(filter).await
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
