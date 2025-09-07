use std::sync::Arc;

use chrono::Utc;
use serde_json::json;

use crate::{
    adapters::database_adapter::DatabaseAdapter,
    parser::{AdapterType, Parser},
    scopes::{
        auth::{Error, Result},
        user::User,
    },
};

#[derive(Clone)]
pub struct UserService {
    adapter: Arc<dyn DatabaseAdapter<User>>,
    adapter_type: AdapterType,
}

impl UserService {
    pub fn new(adapter: Arc<dyn DatabaseAdapter<User>>, adapter_type: AdapterType) -> Self {
        Self {
            adapter,
            adapter_type,
        }
    }

    pub async fn find(&self, user_id: String) -> Result<User> {
        let filter = Parser::mode(self.adapter_type).convert(json!({"id": user_id}));

        self.adapter.find_one(filter).await.ok_or_else(|| {
            tracing::error!("Failed to find user by id: {}", user_id);
            Error::UserNotFound
        })
    }

    pub async fn find_by_email(&self, email: &str) -> Result<User> {
        let filter = Parser::mode(self.adapter_type).convert(json!( {"email": email}));

        self.adapter.find_one(filter).await.ok_or_else(|| {
            tracing::error!("Failed to find user by email");
            Error::UserNotFound
        })
    }

    pub async fn insert(&self, user: &User) -> Result<String> {
        let id = self.adapter.insert(user.to_owned()).await.map_err(|e| {
            tracing::error!("Failed to insert new user to Database: {:?}", e);
            Error::UserCreationFailure
        })?;

        Ok(id)
    }

    pub async fn update_password(&self, user_id: String, password: String) -> Result<User> {
        let filter = Parser::mode(self.adapter_type).convert(json!({"id": user_id}));
        let update = json!({ "$set": json!({"password": password}) });
        let update = Parser::mode(self.adapter_type).convert(update);

        let user = self
            .adapter
            .find_one_and_update(filter, update)
            .await
            .ok_or_else(|| db_error("update password", user_id))?;

        Ok(user)
    }

    pub async fn update_reset_window(&self, user_id: String) -> Result<()> {
        let filter = Parser::mode(self.adapter_type).convert(json!({"id": user_id}));
        let update = json!({
            "$set": json!({
                "passwordResetWindowStart": Utc::now().to_rfc3339()
            })
        });
        let update = Parser::mode(self.adapter_type).convert(update);

        self.adapter
            .find_one_and_update(filter, update)
            .await
            .ok_or_else(|| db_error("reset window start", user_id))?;

        Ok(())
    }

    pub async fn increment_reset_count(&self, user_id: String) -> Result<User> {
        let filter = Parser::mode(self.adapter_type).convert(json!({"id": user_id}));
        let update = json!( { "$inc": json!({"passwordResetCount": 1}) });
        let update = Parser::mode(self.adapter_type).convert(update);

        self.adapter
            .find_one_and_update(filter, update)
            .await
            .ok_or_else(|| db_error("reset counter", user_id))
    }

    pub async fn reset_password_state(&self, user_id: String) -> Result<User> {
        let filter = Parser::mode(self.adapter_type).convert(json!({"id": user_id}));
        let update = json!({
            "$set": json! ({
                "lastPasswordReset": Utc::now().to_rfc3339(),
                "passwordResetCount": 0,
                "failedResetAttempts": 0
            })
        });
        let update = Parser::mode(self.adapter_type).convert(update);

        self.adapter
            .find_one_and_update(filter, update)
            .await
            .ok_or_else(|| db_error("update last password reset time", user_id))
    }
}

fn db_error(msg: &str, user_id: String) -> Error {
    tracing::error!("Failed to {} for user: {}", msg, user_id);
    Error::DatabaseError
}
