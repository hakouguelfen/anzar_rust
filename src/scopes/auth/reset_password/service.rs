use std::sync::Arc;

use crate::{
    adapters::DatabaseAdapter,
    config::AdapterType,
    error::{Error, Result},
    utils::parser::Parser,
};

use super::model::PasswordResetToken;
use chrono::Utc;
use serde_json::json;

#[derive(Clone)]
pub struct PasswordResetTokenService {
    adapter: Arc<dyn DatabaseAdapter<PasswordResetToken>>,
    adapter_type: AdapterType,
}

impl PasswordResetTokenService {
    pub fn new(
        adapter: Arc<dyn DatabaseAdapter<PasswordResetToken>>,
        adapter_type: AdapterType,
    ) -> Self {
        Self {
            adapter,
            adapter_type,
        }
    }

    pub async fn revoke(&self, user_id: String) -> Result<()> {
        let filter = Parser::mode(self.adapter_type).convert(json!({"userId": user_id}));
        let update = json! ({ "$set": json! ({"valid": false}) });
        let update = Parser::mode(self.adapter_type).convert(update);

        self.adapter
            .update_many(filter, update)
            .await
            .map_err(|e| {
                tracing::error!("Failed to revoke password tokens: {:?}", e);
                Error::TokenRevocationFailed {
                    token_id: "".into(),
                }
            })?;

        Ok(())
    }

    pub async fn insert(&self, otp: PasswordResetToken) -> Result<()> {
        self.adapter.insert(otp).await.map(|_| ()).map_err(|e| {
            tracing::error!("Failed to insert password reset token to database: {:?}", e);
            Error::TokenCreationFailed {
                token_type: crate::error::TokenErrorType::PasswordResetToken,
            }
        })
    }

    pub async fn find(&self, hash: String) -> Result<PasswordResetToken> {
        let filter = Parser::mode(self.adapter_type).convert(json!({"tokenHash": hash}));

        self.adapter.find_one(filter).await.ok_or({
            tracing::error!("Password reset token not found");
            Error::TokenNotFound { token_id: hash }
        })
    }

    pub async fn invalidate(&self, id: String) -> Result<PasswordResetToken> {
        let filter = Parser::mode(self.adapter_type).convert(json!({"id": id}));
        let update = json! ({
            "$set": json! ({
                "valid": false,
                "usedAt": Utc::now().to_string()
            })
        });
        let update = Parser::mode(self.adapter_type).convert(update);

        self.adapter
            .find_one_and_update(filter, update)
            .await
            .ok_or({
                tracing::error!("Failed to invalidate token");
                Error::DatabaseError
            })
    }
}
