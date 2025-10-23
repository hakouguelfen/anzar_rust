use std::sync::Arc;

use chrono::{Duration, Utc};
use serde_json::json;

use super::User;
use crate::{
    adapters::DatabaseAdapter,
    config::DatabaseDriver,
    error::{Error, Result},
    utils::parser::Parser,
};

#[derive(Clone)]
pub struct UserRepository {
    adapter: Arc<dyn DatabaseAdapter<User>>,
    database_driver: DatabaseDriver,
}

impl UserRepository {
    pub fn new(adapter: Arc<dyn DatabaseAdapter<User>>, database_driver: DatabaseDriver) -> Self {
        Self {
            adapter,
            database_driver,
        }
    }

    pub async fn find(&self, user_id: &str) -> Result<User> {
        let filter = Parser::mode(self.database_driver).convert(json!({"id": user_id}));

        match self.adapter.find_one(filter).await {
            Ok(Some(user)) => Ok(user),
            Ok(None) => {
                tracing::error!("Failed to find user by id: {}", user_id);
                Err(Error::UserNotFound {
                    user_id: Some(user_id.into()),
                    email: None,
                })
            }
            Err(err) => Err(err),
        }
    }

    pub async fn find_by_email(&self, email: &str) -> Result<User> {
        let filter = Parser::mode(self.database_driver).convert(json!( {"email": email}));

        match self.adapter.find_one(filter).await {
            Ok(Some(user)) => Ok(user),
            Ok(None) => {
                tracing::error!("Failed to find user by email");
                Err(Error::UserNotFound {
                    user_id: None,
                    email: Some(email.into()),
                })
            }
            Err(err) => Err(err),
        }
    }

    pub async fn insert(&self, user: &User) -> Result<String> {
        self.adapter
            .insert(user.to_owned())
            .await
            .map_err(|_| Error::InvalidCredentials {
                field: crate::error::CredentialField::Email,
                reason: crate::error::FailureReason::AlreadyExist,
            })
    }

    pub async fn update_password(&self, user_id: &str, password: &str) -> Result<User> {
        let filter = Parser::mode(self.database_driver).convert(json!({"id": user_id}));
        let update = json!({ "$set": json!({"password": password}) });
        let update = Parser::mode(self.database_driver).convert(update);

        match self.adapter.find_one_and_update(filter, update).await {
            Ok(Some(user)) => Ok(user),
            Ok(None) => Err(Error::InvalidRequest),
            Err(err) => Err(err),
        }
    }

    pub async fn validate_account(&self, user_id: &str) -> Result<User> {
        let filter = Parser::mode(self.database_driver).convert(json!({"id": user_id}));
        let update = json!({ "$set": json!({"verified": true}) });
        let update = Parser::mode(self.database_driver).convert(update);

        match self.adapter.find_one_and_update(filter, update).await {
            Ok(Some(user)) => Ok(user),
            Ok(None) => Err(Error::InvalidRequest),
            Err(err) => Err(err),
        }
    }

    pub async fn update_reset_window(&self, user_id: &str) -> Result<()> {
        let filter = Parser::mode(self.database_driver).convert(json!({"id": user_id}));
        let update = json!({
            "$set": json!({
                "passwordResetWindowStart": Utc::now().to_rfc3339()
            })
        });
        let update = Parser::mode(self.database_driver).convert(update);

        match self.adapter.find_one_and_update(filter, update).await {
            Ok(Some(_user)) => Ok(()),
            Ok(None) => Err(Error::InvalidRequest),
            Err(err) => Err(err),
        }
    }

    pub async fn increment_reset_count(&self, user_id: &str) -> Result<User> {
        let filter = Parser::mode(self.database_driver).convert(json!({"id": user_id}));
        let update = json!( { "$inc": json!({"passwordResetCount": 1}) });
        let update = Parser::mode(self.database_driver).convert(update);

        match self.adapter.find_one_and_update(filter, update).await {
            Ok(Some(user)) => Ok(user),
            Ok(None) => Err(Error::InvalidRequest),
            Err(err) => Err(err),
        }
    }

    pub async fn increment_failed_login_attempts(&self, user_id: &str) -> Result<User> {
        let filter = Parser::mode(self.database_driver).convert(json!({"id": user_id}));
        let update = json!( { "$inc": json!({"failedLoginAttempts": 1}) });
        let update = Parser::mode(self.database_driver).convert(update);

        match self.adapter.find_one_and_update(filter, update).await {
            Ok(Some(user)) => Ok(user),
            Ok(None) => Err(Error::InvalidRequest),
            Err(err) => Err(err),
        }
    }

    pub async fn lock_account(&self, user_id: &str, lockout_duration: i64) -> Result<User> {
        let filter = Parser::mode(self.database_driver).convert(json!({"id": user_id}));
        let update = json!( {
            "$set": json!({
                "lockedUntil": (Utc::now() + Duration::seconds(lockout_duration)),
                "accountLocked": true
            })
        });
        let update = Parser::mode(self.database_driver).convert(update);

        match self.adapter.find_one_and_update(filter, update).await {
            Ok(Some(user)) => Ok(user),
            Ok(None) => Err(Error::InvalidRequest),
            Err(err) => Err(err),
        }
    }
    pub async fn unlock_account(&self, user_id: &str) -> Result<User> {
        let filter = Parser::mode(self.database_driver).convert(json!({"id": user_id}));
        let update = json!( {
            "$set": json!({
                "lockedUntil": None::<chrono::DateTime<Utc>>,
                "accountLocked": false
            })
        });
        let update = Parser::mode(self.database_driver).convert(update);

        match self.adapter.find_one_and_update(filter, update).await {
            Ok(Some(user)) => Ok(user),
            Ok(None) => Err(Error::InvalidRequest),
            Err(err) => Err(err),
        }
    }

    pub async fn reset_failed_login_attempts(&self, user_id: &str) -> Result<User> {
        let filter = Parser::mode(self.database_driver).convert(json!({"id": user_id}));
        let update = json!( {
            "$set": json!({
                "failedLoginAttempts": 0,
                "lockedUntil": None::<chrono::DateTime<Utc>>
            })
        });
        let update = Parser::mode(self.database_driver).convert(update);

        match self.adapter.find_one_and_update(filter, update).await {
            Ok(Some(user)) => Ok(user),
            Ok(None) => Err(Error::InvalidRequest),
            Err(err) => Err(err),
        }
    }

    pub async fn reset_password_state(&self, user_id: &str) -> Result<User> {
        let filter = Parser::mode(self.database_driver).convert(json!({"id": user_id}));
        let update = json!({
            "$set": json! ({
                "lastPasswordReset": Utc::now(),
                "passwordResetCount": 0,
                "failedResetAttempts": 0,
                "failedLoginAttempts": 0
            })
        });
        let update = Parser::mode(self.database_driver).convert(update);

        match self.adapter.find_one_and_update(filter, update).await {
            Ok(Some(user)) => Ok(user),
            Ok(None) => Err(Error::InvalidRequest),
            Err(err) => Err(err),
        }
    }
}
