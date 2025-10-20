use std::sync::Arc;

use crate::{
    adapters::DatabaseAdapter,
    config::DatabaseDriver,
    error::{Error, InvalidTokenReason, Result, TokenErrorType},
    scopes::email::model::EmailVerificationToken,
    utils::parser::Parser,
};

use chrono::Utc;
use serde_json::json;

#[derive(Clone)]
pub struct EmailVerificationTokenRepository {
    adapter: Arc<dyn DatabaseAdapter<EmailVerificationToken>>,
    database_driver: DatabaseDriver,
}

impl EmailVerificationTokenRepository {
    pub fn new(
        adapter: Arc<dyn DatabaseAdapter<EmailVerificationToken>>,
        database_driver: DatabaseDriver,
    ) -> Self {
        Self {
            adapter,
            database_driver,
        }
    }

    pub async fn revoke(&self, user_id: &str) -> Result<()> {
        let filter = Parser::mode(self.database_driver).convert(json!({"userId": user_id}));
        let update = json! ({ "$set": json! ({"valid": false}) });
        let update = Parser::mode(self.database_driver).convert(update);

        self.adapter
            .update_many(filter, update)
            .await
            .map_err(|e| {
                tracing::error!("Failed to revoke email verification tokens: {:?}", e);
                Error::TokenRevocationFailed {
                    token_id: "".into(),
                }
            })?;

        Ok(())
    }

    pub async fn insert(&self, otp: EmailVerificationToken) -> Result<()> {
        self.adapter.insert(otp).await.map(|_| ()).map_err(|e| {
            tracing::error!(
                "Failed to insert email verification token to database: {:?}",
                e
            );
            Error::TokenCreationFailed {
                token_type: crate::error::TokenErrorType::EmailVerificationToken,
            }
        })
    }

    pub async fn find(&self, hash: &str) -> Result<EmailVerificationToken> {
        let filter = Parser::mode(self.database_driver).convert(json!({"token": hash}));

        match self.adapter.find_one(filter).await {
            Ok(Some(token)) => Ok(token),
            Ok(None) => Err(Error::InvalidToken {
                token_type: TokenErrorType::EmailVerificationToken,
                reason: InvalidTokenReason::NotFound,
            }),
            Err(err) => Err(err),
        }
    }

    pub async fn invalidate(&self, id: &str) -> Result<EmailVerificationToken> {
        let filter = Parser::mode(self.database_driver).convert(json!({"id": id}));
        let update = json! ({
            "$set": json! ({
                "valid": false,
                "usedAt": Utc::now().to_string()
            })
        });
        let update = Parser::mode(self.database_driver).convert(update);

        self.adapter
            .find_one_and_update(filter, update)
            .await
            .ok_or({
                tracing::error!("Failed to invalidate token");
                Error::DatabaseError("".into())
            })
    }
}
