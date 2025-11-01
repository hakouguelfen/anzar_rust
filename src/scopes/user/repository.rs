use std::sync::Arc;

use chrono::Utc;
use serde_json::json;

use super::User;
use crate::{
    adapters::{DatabaseAdapter, memcache::MemCacheAdapter},
    config::DatabaseDriver,
    error::{Error, Result},
    utils::parser::Parser,
};

#[derive(Clone)]
pub struct UserRepository {
    adapter: Arc<dyn DatabaseAdapter<User>>,
    database_driver: DatabaseDriver,
    memcache: MemCacheAdapter,
}

impl UserRepository {
    pub fn new(
        adapter: Arc<dyn DatabaseAdapter<User>>,
        database_driver: DatabaseDriver,
        memcache: MemCacheAdapter,
    ) -> Self {
        Self {
            adapter,
            database_driver,
            memcache,
        }
    }
    // Memcache
    pub fn increment(&self, key: &str) -> u8 {
        self.memcache.increment(key)
    }
    pub fn put_cookie_in_lockout(&self, key: &str, expiration: u32) -> Result<()> {
        Ok(self.memcache.lock_account(key, expiration)?)
    }
    pub fn exists(&self, key: &str) -> bool {
        self.memcache.exists(key)
    }

    // Database
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

    pub async fn lock_account(&self, user_id: &str) -> Result<User> {
        let filter = Parser::mode(self.database_driver).convert(json!({"id": user_id}));
        let update = json!( {
            "$set": json!({
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

    pub async fn reset_password_state(&self, user_id: &str) -> Result<User> {
        let filter = Parser::mode(self.database_driver).convert(json!({"id": user_id}));
        let update = json!({
            "$set": json! ({
                "lastPasswordReset": Utc::now(),
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
